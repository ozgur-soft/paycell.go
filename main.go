package main

import (
	"log"

	paycell "github.com/ozgur-soft/paycell/src"
)

func main() {
	api := new(paycell.API)
	api.Mode = "TEST"          // "PROD","TEST"
	api.MSisdn = "5332109727"  // Müşteri telefon numarası
	api.ClientIP = "127.0.0.1" // Müşteri ip adresi
	get := api.GetPaymentMethods()
	if get.PaymentMethods.Header.ResponseCode == "0" {
		if !get.PaymentMethods.MobilePayment.IsDcbOpen {
			switch get.PaymentMethods.MobilePayment.IsEulaExpired {
			case true: // Sözleşmesi Güncel Olmayan Müşteri İçin
				if get.PaymentMethods.MobilePayment.EulaId != "" {
					open := api.OpenMobilePayment(get.PaymentMethods.MobilePayment.EulaId)
					if open.MobilePayment.Header.ResponseCode == "0" {
						log.Println("mobil ödeme açıldı")
					}
				}
			case false: // Sözleşmesi Güncel Olan Müşteri İçin
				if get.PaymentMethods.MobilePayment.SignedEulaId != "" {
					open := api.OpenMobilePayment(nil)
					if open.MobilePayment.Header.ResponseCode == "0" {
						log.Println("mobil ödeme açıldı")
					}
				}
			}
		}
		amount := "100" // Satış tutarı (1,00 -> 100) Son 2 hane kuruş
		send := api.SendOTP(amount)
		if send.OTP.Header.ResponseCode == "0" {
			log.Println("otp gönderildi")
		}
		otp := "" // Müşteriye gönderilen tek kullanımlık şifre
		validate := api.ValidateOTP(send.OTP.Token, otp, amount)
		if validate.OTP.Header.ResponseCode == "0" {
			log.Println("otp doğrulandı")
		}
	}
}
