package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
class PaymentControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    @Qualifier("creditCardsJdbcTemplate")
    private JdbcTemplate creditCardsJdbcTemplate;

    @Test
    void testSqlInjectionAttemptInCreditCardParameter() throws Exception {
        String maliciousInput = "1234'; DROP TABLE credit_card; --";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousInput)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        Long tableCount = creditCardsJdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'credit_card'",
            Long.class
        );
        
        assert tableCount != null && tableCount > 0 : "Table should still exist after SQL injection attempt";
    }

    @Test
    void testSqlInjectionAttemptInShipmentIdParameter() throws Exception {
        String creditCard = "4111111111111111";
        String maliciousShipmentId = "1 OR 1=1; DROP TABLE shipment; --";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk());

        Long tableCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'shipment'",
            Long.class
        );
        
        assert tableCount != null && tableCount > 0 : "Table should still exist after SQL injection attempt";
    }

    @Test
    void testValidPaymentProcessing() throws Exception {
        String creditCard = "4111111111111111";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].success").value(true))
                .andExpect(jsonPath("$[0].shipment_id").value(shipmentId))
                .andExpect(jsonPath("$[0].credit_card").value("XXXX-XXXX-XXXX-1111"));
    }

    @Test
    void testMissingParameters() throws Exception {
        mockMvc.perform(get("/payments"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").exists());
    }

    @Test
    void testSpecialCharactersInCreditCard() throws Exception {
        String creditCardWithSpecialChars = "4111'\"--1111";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCardWithSpecialChars)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());
    }

    @Test
    void testUnionBasedSqlInjectionAttempt() throws Exception {
        String maliciousInput = "1' UNION SELECT card_number, shipment_id FROM credit_card --";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousInput)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());
    }
}
