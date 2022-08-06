# paycell

```go
package main

import (
	"log"

	paycell "github.com/ozgur-soft/paycell/src"
)

func main() {
	api := paycell.Api("905591111177")
	api.SetMode("TEST")           // "PROD","TEST"
	api.SetIPAddress("127.0.0.1") // Müşteri ip adresi
	api.SetAmount("1.00", "TRY")  // Satış tutarı
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
				if send.OTP.Token != nil {
					otp := ""
					validate := api.ValidateOTP(send.OTP.Token, otp)
					if validate.OTP.Header.ResponseCode == "0" {
						pay := api.Auth()
						if pay.Provision.Header.ResponseCode == "0" {
							log.Println("ödeme başarılı")
						}
					}
				}
			}
		}
	}
}
```