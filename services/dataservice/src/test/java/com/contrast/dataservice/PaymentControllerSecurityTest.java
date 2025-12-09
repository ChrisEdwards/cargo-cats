package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
class PaymentControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testSqlInjectionInCreditCardParameter() throws Exception {
        String sqlInjectionPayload = "1234'; DROP TABLE credit_card; --";
        
        mockMvc.perform(get("/payments")
                .param("creditCard", sqlInjectionPayload)
                .param("shipmentId", "1"))
                .andExpect(status().isOk());
    }

    @Test
    void testSqlInjectionInShipmentIdParameter() throws Exception {
        String sqlInjectionPayload = "1 OR 1=1";
        
        mockMvc.perform(get("/payments")
                .param("creditCard", "4111111111111111")
                .param("shipmentId", sqlInjectionPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));
    }

    @Test
    void testValidPaymentRequest() throws Exception {
        mockMvc.perform(get("/payments")
                .param("creditCard", "4111111111111111")
                .param("shipmentId", "123"))
                .andExpect(status().isOk());
    }

    @Test
    void testMissingParameters() throws Exception {
        mockMvc.perform(get("/payments"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Both creditCard and shipmentId parameters are required for payment processing"));
    }

    @Test
    void testNonNumericShipmentId() throws Exception {
        mockMvc.perform(get("/payments")
                .param("creditCard", "4111111111111111")
                .param("shipmentId", "abc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));
    }

    @Test
    void testShipmentIdWithSpecialCharacters() throws Exception {
        mockMvc.perform(get("/payments")
                .param("creditCard", "4111111111111111")
                .param("shipmentId", "123'; DELETE FROM shipment; --"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));
    }
}
