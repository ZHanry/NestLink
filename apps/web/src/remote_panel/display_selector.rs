use leptos::prelude::*;
use nestlink_web::{browser_peer::PeerDisplaySnapshot, i18n::text as t};

#[component]
pub(super) fn RemoteDisplaySelector(
    snapshot: RwSignal<Option<PeerDisplaySnapshot>>,
    switching: RwSignal<bool>,
    active: RwSignal<bool>,
    select: Callback<u32>,
) -> impl IntoView {
    // Selection/status updates must not replace the option nodes after the
    // select's value property has already been applied.
    let catalog = Memo::new(move |_| {
        snapshot.with(|value| {
            value
                .as_ref()
                .map(|value| value.displays.clone())
                .unwrap_or_default()
        })
    });
    view! {
        <Show when=move || snapshot.with(Option::is_some)>
            <div class="remote-display-selector">
                <label for="remote-display-source">{move || t("显示器", "Display")}</label>
                <select id="remote-display-source"
                    disabled=move || !active.get() || switching.get()
                        || snapshot.with(|value| value.as_ref().is_none_or(|value| value.displays.len() < 2))
                    prop:value=move || snapshot.with(|value| value.as_ref().and_then(|value| {
                        value.pending_source.or_else(|| value.selected.as_ref().map(|selection| selection.source))
                    }).map(|source| source.to_string()).unwrap_or_default())
                    on:change=move |event| {
                        if let Ok(source) = event_target_value(&event).parse() {
                            select.run(source);
                        }
                    }>
                    {move || catalog.get().into_iter().map(|display| {
                        let label = format!("{} · {} × {}", display.label, display.width, display.height);
                        view! { <option value=display.source.to_string()>{label}</option> }
                    }).collect_view()}
                </select>
                <span role="status" aria-live="polite">{move || if switching.get() {
                    t("正在切换…", "Switching…")
                } else {
                    t("仅显示设备本机批准的屏幕", "Displays approved on the remote device")
                }}</span>
            </div>
        </Show>
    }
}
