use jni::{
    JavaVM,
    objects::{GlobalRef, JObject, JValue},
};
use nestlink_remote::input::{Button, InputAction, InputDevice, InputLayout, PlatformInput};
use std::io;

/// Synchronous Core adapter backed by an explicitly enabled Android
/// AccessibilityService and, for text/key actions, the active NestLink IME.
pub(crate) struct AndroidInputDevice {
    vm: JavaVM,
    bridge: GlobalRef,
}

impl AndroidInputDevice {
    pub(crate) fn new(vm: JavaVM, bridge: GlobalRef) -> Self {
        Self { vm, bridge }
    }

    fn call_bool(
        &self,
        method: &str,
        signature: &str,
        args: &[JValue<'_, '_>],
    ) -> io::Result<bool> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("Android input JVM attachment failed"))?;
        match env
            .call_method(self.bridge.as_obj(), method, signature, args)
            .and_then(|value| value.z())
        {
            Ok(value) => Ok(value),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err(io::Error::other(
                    "Android input service rejected the action",
                ))
            }
        }
    }

    fn accepted(&self, method: &str, signature: &str, args: &[JValue<'_, '_>]) -> io::Result<()> {
        if self.call_bool(method, signature, args)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android input service is unavailable or rejected the action",
            ))
        }
    }
}

impl InputDevice for AndroidInputDevice {
    fn select_source(&mut self, source: u32, layout: InputLayout) -> io::Result<()> {
        // A Projection grant can only retain its one already verified source.
        // Accessibility checks the same encoded geometry before any handoff.
        if source != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ungranted Android input source",
            ));
        }
        self.accepted(
            "selectSource",
            "(IIIII)Z",
            &[
                JValue::Int(0),
                JValue::Int(layout.left),
                JValue::Int(layout.top),
                JValue::Int(
                    i32::try_from(layout.width)
                        .map_err(|_| io::Error::other("input width overflow"))?,
                ),
                JValue::Int(
                    i32::try_from(layout.height)
                        .map_err(|_| io::Error::other("input height overflow"))?,
                ),
            ],
        )
    }

    fn check(&mut self) -> io::Result<()> {
        self.accepted("isAccessibilityRunning", "()Z", &[])
    }

    fn reset(&mut self) -> io::Result<()> {
        self.accepted("releasePointer", "()Z", &[])
    }

    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        match input {
            PlatformInput::Action(InputAction::Key { code, down }) => self.accepted(
                "sendHidKey",
                "(IZ)Z",
                &[JValue::Int(i32::from(*code)), JValue::Bool(u8::from(*down))],
            ),
            PlatformInput::Action(InputAction::Pointer { button, down, x, y }) => {
                let phase = match (button, down) {
                    (Some(1), true) => 1,
                    (None, false) => 2,
                    (Some(1), false) => 3,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "Android supports primary touch input only",
                        ));
                    }
                };
                self.accepted(
                    "dispatchPointer",
                    "(III)Z",
                    &[JValue::Int(*x), JValue::Int(*y), JValue::Int(phase)],
                )
            }
            PlatformInput::Action(InputAction::Text(text)) => {
                let mut env = self
                    .vm
                    .attach_current_thread()
                    .map_err(|_| io::Error::other("Android input JVM attachment failed"))?;
                let text = env
                    .new_string(text)
                    .map_err(|_| io::Error::other("Android input text could not be prepared"))?;
                let object = JObject::from(text);
                match env
                    .call_method(
                        self.bridge.as_obj(),
                        "commitRemoteText",
                        "(Ljava/lang/String;)Z",
                        &[JValue::Object(&object)],
                    )
                    .and_then(|value| value.z())
                {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "NestLink IME has no active text target",
                    )),
                    Err(_) => {
                        if env.exception_check().unwrap_or(false) {
                            let _ = env.exception_clear();
                        }
                        Err(io::Error::other("NestLink IME rejected remote text"))
                    }
                }
            }
            PlatformInput::Release(Button::Key(code)) => self.accepted(
                "sendHidKey",
                "(IZ)Z",
                &[JValue::Int(i32::from(code)), JValue::Bool(0)],
            ),
            PlatformInput::Release(Button::Pointer(_)) => {
                self.accepted("releasePointer", "()Z", &[])
            }
        }
    }
}
