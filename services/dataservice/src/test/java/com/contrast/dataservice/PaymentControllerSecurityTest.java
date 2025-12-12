package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class PaymentControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    @Qualifier("creditCardsJdbcTemplate")
    private JdbcTemplate creditCardsJdbcTemplate;

    @Test
    void testSqlInjectionInCreditCardParameter() throws Exception {
        String maliciousCreditCard = "1234'; DROP TABLE credit_card; --";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        Integer tableCount = creditCardsJdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'credit_card'",
            Integer.class
        );
        
        assert tableCount != null && tableCount == 1 : "credit_card table should still exist after SQL injection attempt";
    }

    @Test
    void testSqlInjectionInShipmentIdParameter() throws Exception {
        String creditCard = "1234567890123456";
        String maliciousShipmentId = "1 OR 1=1; DROP TABLE shipment; --";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk());

        Integer tableCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'shipment'",
            Integer.class
        );
        
        assert tableCount != null && tableCount == 1 : "shipment table should still exist after SQL injection attempt";
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
                .andExpect(jsonPath("$[0].message").value("Both creditCard and shipmentId parameters are required for payment processing"));
    }

    @Test
    void testSqlInjectionWithUnionAttack() throws Exception {
        String maliciousCreditCard = "1234' UNION SELECT id, card_number, shipment_id FROM credit_card WHERE '1'='1";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());
    }

    @Test
    void testSqlInjectionInBothParameters() throws Exception {
        String maliciousCreditCard = "1234'; DELETE FROM credit_card WHERE '1'='1";
        String maliciousShipmentId = "1; DELETE FROM shipment WHERE 1=1; --";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk());
    }
}
