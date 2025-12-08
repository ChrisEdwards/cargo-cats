package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class PaymentControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testSqlInjectionAttemptInCreditCardParameter() throws Exception {
        String sqlInjectionPayload = "1234'; DROP TABLE credit_card; --";
        String shipmentId = "1";
        
        mockMvc.perform(get("/payments")
                .param("creditCard", sqlInjectionPayload)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());
    }

    @Test
    void testSqlInjectionAttemptInShipmentIdParameter() throws Exception {
        String creditCard = "4111111111111111";
        String sqlInjectionPayload = "1 OR 1=1";
        
        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", sqlInjectionPayload))
                .andExpect(status().isOk());
    }

    @Test
    void testSqlInjectionAttemptInBothParameters() throws Exception {
        String creditCardInjection = "1234' OR '1'='1";
        String shipmentIdInjection = "1 OR 1=1; DROP TABLE shipment; --";
        
        mockMvc.perform(get("/payments")
                .param("creditCard", creditCardInjection)
                .param("shipmentId", shipmentIdInjection))
                .andExpect(status().isOk());
    }

    @Test
    void testNormalPaymentRequest() throws Exception {
        String creditCard = "4111111111111111";
        String shipmentId = "123";
        
        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());
    }

    @Test
    void testPaymentRequestWithSpecialCharacters() throws Exception {
        String creditCard = "4111-1111-1111-1111";
        String shipmentId = "456";
        
        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());
    }
}
