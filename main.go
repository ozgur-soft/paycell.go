package main

import (
	"fmt"
	"log"

	paycell "github.com/ozgur-soft/paycell/src"
)

func main() {
	api := new(paycell.API)
	api.Mode = "TEST"           // "PROD","TEST"
	api.MSisdn = "905591111177" // Müşteri telefon numarası
	api.ClientIP = "127.0.0.1"  // Müşteri ip adresi
	api.Amount = "100"          // Satış tutarı (1,00 -> 100) Son 2 hane kuruş
	api.Currency = "TRY"        // Para birimi
	token := token(api)
	if token != nil {
		fmt.Println(token)
		otp := ""
		valid := validate(api, token, otp)
		if valid {
			pay(api)
		}
	}
}

func token(api *paycell.API) (token interface{}) {
	get := api.GetPaymentMethods()
	if get.PaymentMethods.Header.ResponseCode == "0" {
		if get.PaymentMethods.MobilePayment != nil {
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
			send := api.SendOTP()
			if send.OTP.Header.ResponseCode == "0" {
				token = send.OTP.Token
			}
		}
	}
	return token
}

func validate(api *paycell.API, token, otp interface{}) bool {
	validate := api.ValidateOTP(token, otp)
	return validate.OTP.Header.ResponseCode == "0"
}

func pay(api *paycell.API) bool {
	pay := api.Auth()
	return pay.Provision.Header.ResponseCode == "0"
}
