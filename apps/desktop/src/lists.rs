use crate::DesktopApp;
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use nestlink_app_core::{Action, Snapshot};
use nestlink_app_ipc::wire::Command;

impl DesktopApp {
    pub(crate) fn devices_table(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let Some(devices) = &snapshot.devices.data else {
            return;
        };
        if devices.is_empty() {
            ui.add_space(24.);
            ui.label(
                RichText::new(self.t("还没有设备", "No devices yet"))
                    .size(19.)
                    .strong(),
            );
            ui.label(self.t(
                "在上方登记此设备，或在其他设备上登录同一账号。",
                "Enroll this device above, or sign in on another device.",
            ));
            return;
        }
        egui::ScrollArea::horizontal()
            .id_salt("devices-table-scroll")
            .show(ui, |ui| {
                ui.set_min_width(440.);
                TableBuilder::new(ui)
                    .striped(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::remainder().at_least(180.))
                    .column(Column::initial(100.).at_least(75.))
                    .column(Column::initial(80.))
                    .column(Column::exact(76.))
                    .header(36., |mut header| {
                        for label in [
                            self.t("设备", "Device"),
                            self.t("平台", "Platform"),
                            self.t("状态", "Status"),
                            self.t("操作", "Action"),
                        ] {
                            header.col(|ui| {
                                ui.strong(label);
                            });
                        }
                    })
                    .body(|mut body| {
                        for view in devices.iter() {
                            body.row(64., |mut row| {
                                row.col(|ui| {
                                    ui.vertical(|ui| {
                                        ui.label(RichText::new(&view.device.name).strong());
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&view.device.id)
                                                    .small()
                                                    .color(ui.visuals().weak_text_color()),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(&view.device.id);
                                    });
                                });
                                row.col(|ui| {
                                    ui.label(&view.device.platform);
                                });
                                row.col(|ui| {
                                    ui.label(self.t(
                                        if view.revoked {
                                            "已撤销"
                                        } else {
                                            "已登记"
                                        },
                                        if view.revoked { "Revoked" } else { "Enrolled" },
                                    ));
                                });
                                row.col(|ui| {
                                    if ui
                                        .add_enabled(
                                            !view.revoked && snapshot.devices.loading.is_none(),
                                            egui::Button::new(self.t("撤销", "Revoke")),
                                        )
                                        .clicked()
                                    {
                                        self.pending_confirmation = Some((
                                            format!(
                                                "{} {}",
                                                self.t("撤销设备：", "Revoke device:"),
                                                view.device.name
                                            ),
                                            Command::Submit {
                                                action: Action::RevokeDevice {
                                                    device_id: view.device.id.clone(),
                                                },
                                            },
                                        ));
                                    }
                                });
                            });
                        }
                    });
            });
    }

    pub(crate) fn accounts_table(&mut self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        let Some(accounts) = &snapshot.accounts.data else {
            return;
        };
        egui::ScrollArea::horizontal()
            .id_salt("accounts-table-scroll")
            .show(ui, |ui| {
                ui.set_min_width(440.);
                TableBuilder::new(ui)
                    .striped(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::remainder().at_least(160.))
                    .column(Column::initial(110.))
                    .column(Column::initial(80.))
                    .column(Column::exact(76.))
                    .header(36., |mut header| {
                        for label in [
                            self.t("账号", "Account"),
                            self.t("角色", "Role"),
                            self.t("状态", "Status"),
                            self.t("操作", "Action"),
                        ] {
                            header.col(|ui| {
                                ui.strong(label);
                            });
                        }
                    })
                    .body(|mut body| {
                        for account in accounts.iter() {
                            body.row(56., |mut row| {
                                row.col(|ui| {
                                    ui.label(RichText::new(&account.name).strong())
                                        .on_hover_text(&account.id);
                                });
                                row.col(|ui| {
                                    ui.label(self.t(
                                        if account.is_admin {
                                            "管理员"
                                        } else {
                                            "普通账号"
                                        },
                                        if account.is_admin {
                                            "Administrator"
                                        } else {
                                            "Standard"
                                        },
                                    ));
                                });
                                row.col(|ui| {
                                    ui.label(self.t(
                                        if account.disabled {
                                            "已禁用"
                                        } else {
                                            "已启用"
                                        },
                                        if account.disabled {
                                            "Disabled"
                                        } else {
                                            "Enabled"
                                        },
                                    ));
                                });
                                row.col(|ui| {
                                    if ui
                                        .add_enabled(
                                            !account.disabled
                                                && !account.is_admin
                                                && snapshot.accounts.loading.is_none(),
                                            egui::Button::new(self.t("禁用", "Disable")),
                                        )
                                        .clicked()
                                    {
                                        self.pending_confirmation = Some((
                                            format!(
                                                "{} {}",
                                                self.t("禁用账号：", "Disable account:"),
                                                account.name
                                            ),
                                            Command::Submit {
                                                action: Action::DisableAccount {
                                                    account_id: account.id.clone(),
                                                },
                                            },
                                        ));
                                    }
                                });
                            });
                        }
                    });
            });
    }
}
