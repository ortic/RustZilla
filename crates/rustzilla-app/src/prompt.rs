//! What a keyboard-interactive login asks (a one-time code, say): the
//! session's worker waits on the answers while the UI shows the questions.

use std::sync::mpsc::{self, Sender};

use rustzilla_remote::{OnPrompt, Prompts};

use crate::icons::Icon;
use crate::theme;

/// The questions, and where the answers go. Dropped unanswered, the login
/// is cancelled.
pub struct Request {
    prompts: Prompts,
    reply: Sender<Option<Vec<String>>>,
}

/// Asks through `send`, blocking the calling thread (the session's) until
/// the UI answers or drops the request.
pub fn asker(send: impl Fn(Request) + Send + Sync + 'static) -> OnPrompt {
    std::sync::Arc::new(move |prompts| {
        let (reply, answers) = mpsc::channel();
        send(Request { prompts, reply });
        answers.recv().ok().flatten()
    })
}

pub struct PromptDialog {
    request: Request,
    answers: Vec<String>,
    /// Focus the first field once.
    focused: bool,
}

impl PromptDialog {
    pub fn new(request: Request) -> Self {
        let answers = vec![String::new(); request.prompts.prompts.len()];
        Self {
            request,
            answers,
            focused: false,
        }
    }

    /// Shows the questions; false once answered or cancelled.
    pub fn show(&mut self, ctx: &egui::Context) -> bool {
        let mut answered = None;
        let modal = egui::Modal::new(egui::Id::new("login-prompt")).show(ctx, |ui| {
            ui.set_width(460.0);
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
            let prompts = &self.request.prompts;
            let title = Some(prompts.name.trim())
                .filter(|n| !n.is_empty())
                .unwrap_or("Login");
            ui.horizontal(|ui| {
                ui.add(Icon::Lock.sized(ui, 36.0));
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(title).heading());
                    ui.add(egui::Label::new(format!("{} asks to log in:", prompts.server)).wrap());
                });
            });
            ui.add_space(10.0);
            if !prompts.instructions.trim().is_empty() {
                ui.add(egui::Label::new(prompts.instructions.trim()).wrap());
                ui.add_space(6.0);
            }
            egui::Grid::new("login-prompts")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    for (index, (prompt, answer)) in
                        prompts.prompts.iter().zip(&mut self.answers).enumerate()
                    {
                        ui.label(prompt.text.trim());
                        let field = ui.add(
                            egui::TextEdit::singleline(answer)
                                .password(!prompt.echo)
                                .margin(egui::Margin::symmetric(8, 6))
                                .desired_width(f32::INFINITY),
                        );
                        if index == 0 && !self.focused {
                            field.request_focus();
                            self.focused = true;
                        }
                        ui.end_row();
                    }
                });
            ui.add_space(12.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::primary_button("Continue")).clicked() || enter {
                    answered = Some(Some(std::mem::take(&mut self.answers)));
                }
                if ui.add(theme::secondary_button("Cancel")).clicked() {
                    answered = Some(None);
                }
            });
        });
        if answered.is_none() && modal.should_close() {
            answered = Some(None);
        }
        match answered {
            Some(answers) => {
                let _ = self.request.reply.send(answers);
                false
            }
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustzilla_remote::Params;
    use rustzilla_remote::testserver::{OTP, TestServer};

    use crate::session::{Event, Session};

    /// The session's worker waits for the code, then logs in.
    #[test]
    fn the_session_waits_for_the_answers() {
        let dir = std::env::temp_dir().join(format!("rustzilla-prompt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
        let mut params = server.params();
        params.username = "otp".into();
        let session = Session::start(
            Params::Sftp(params),
            String::new(),
            egui::Context::default(),
        );
        let mut asked = 0;
        loop {
            match session.rx.recv_timeout(Duration::from_secs(20)).unwrap() {
                Event::Prompt(request) => {
                    asked += 1;
                    assert_eq!(request.prompts.prompts[0].text, "Verification code: ");
                    request.reply.send(Some(vec![OTP.to_owned()])).unwrap();
                }
                Event::Connected { .. } => break,
                Event::Failed(e) => panic!("{e}"),
                _ => {}
            }
        }
        assert_eq!(asked, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
