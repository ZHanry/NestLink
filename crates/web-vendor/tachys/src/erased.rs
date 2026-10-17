// Review candidate: standard-library storage replaces the external erased crate.
// Preserve the upstream Tachys package attribution and license when integrating.
use std::any::Any;

macro_rules! erased {
    ([$($bounds:tt)*], $name:ident, $storage:ty) => {
        /// A value stored with checked standard-library type erasure.
        pub struct $name {
            value: Box<$storage>,
        }

        impl $name {
            /// Stores a value and preserves its concrete destructor.
            pub fn new<T: $($bounds)*>(item: T) -> Self {
                Self { value: Box::new(item) }
            }

            /// Borrows the value after checking its actual type.
            pub fn get_ref<T: 'static>(&self) -> &T {
                self.value.downcast_ref::<T>().expect("Erased: type mismatch")
            }

            /// Mutably borrows the value after checking its actual type.
            pub fn get_mut<T: 'static>(&mut self) -> &mut T {
                self.value.downcast_mut::<T>().expect("Erased: type mismatch")
            }

            /// Moves the value out after checking its actual type.
            pub fn into_inner<T: 'static>(self) -> T {
                *self.value.downcast::<T>().unwrap_or_else(|_| panic!("Erased: type mismatch"))
            }
        }
    };
}

erased!([Send + 'static], Erased, dyn Any + Send);
erased!(['static], ErasedLocal, dyn Any);
