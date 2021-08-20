package main

import (
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-soft/paycell/src"
)

func main() {
	api := new(paycell.API)
	api.Mode = "TEST"          // "PROD","TEST"
	api.MSisdn = "5332149727"  // Müşteri telefon numarası
	api.ClientIP = "127.0.0.1" // Müşteri ip adresi
	get := api.GetPaymentMethods()
	if get.PaymentMethods.MobilePayment.IsDcbOpen {
		pretty, _ := json.MarshalIndent(get.PaymentMethods, " ", "\t")
		fmt.Println(string(pretty))
	} else {
		switch get.PaymentMethods.MobilePayment.IsEulaExpired {
		case true: // Sözleşmesi Güncel Olmayan Müşteri İçin
			eulaid := get.PaymentMethods.MobilePayment.EulaId
			open := api.OpenMobilePayment(eulaid)
			pretty, _ := json.MarshalIndent(open.MobilePayment, " ", "\t")
			fmt.Println(string(pretty))
		case false: // Sözleşmesi Güncel Olan Müşteri İçin
			open := api.OpenMobilePayment(nil)
			pretty, _ := json.MarshalIndent(open.MobilePayment, " ", "\t")
			fmt.Println(string(pretty))
		}
	}
	amount := "100" // Satış tutarı (1,00 -> 100) Son 2 hane kuruş
	send := api.SendOTP(amount)
	pretty, _ := json.MarshalIndent(send.OTP, " ", "\t")
	fmt.Println(string(pretty))
}
