package mailer

import (
	"gopkg.in/gomail.v2"
)

type MailerUC struct {
	RootMail         string
	RootMailPassword string
	dialer           *gomail.Dialer
}

func NewMailer(rootMail, rootMailPassword string) *MailerUC {
	m := MailerUC{
		RootMail:         rootMail,
		RootMailPassword: rootMailPassword,
	}
	m.dialer = gomail.NewDialer("smtp.gmail.com", 587, m.RootMail, m.RootMailPassword)
	return &m
}

func (m *MailerUC) SendWarning(email string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", m.RootMail)
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", "IP Change")
	msg.SetBody("text/plain", "Attention, the IP address has changed since the last authorization!")

	err := m.dialer.DialAndSend(msg)
	return err
}
