package main

import (
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-soft/paycell/src"
)

func main() {
	msisdn := "5325628808"      // Müşteri telefon numarası
	clientip := "127.0.0.1"     // Müşteri ip adresi
	api := &paycell.API{"TEST"} // "PROD","TEST"
	response := api.GetPaymentMethods(msisdn, clientip)
	if response.PaymentMethods.MobilePayment.IsDcbOpen {
		pretty, _ := json.MarshalIndent(response.PaymentMethods, " ", "\t")
		fmt.Println(string(pretty))
	} else {
		switch response.PaymentMethods.MobilePayment.IsEulaExpired {
		case true: // Sözleşmesi Güncel Olmayan Müşteri İçin
			eulaid := response.PaymentMethods.MobilePayment.EulaId
			response := api.OpenMobilePayment(msisdn, eulaid, clientip)
			pretty, _ := json.MarshalIndent(response.PaymentMethods, " ", "\t")
			fmt.Println(string(pretty))
		case false: // Sözleşmesi Güncel Olan Müşteri İçin
			response := api.OpenMobilePayment(msisdn, nil, clientip)
			pretty, _ := json.MarshalIndent(response.PaymentMethods, " ", "\t")
			fmt.Println(string(pretty))
		}
	}
}
