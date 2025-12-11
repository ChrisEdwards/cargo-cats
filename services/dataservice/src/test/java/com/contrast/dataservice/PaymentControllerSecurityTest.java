package com.contrast.dataservice;

import org.junit.jupiter.api.BeforeEach;
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

    @BeforeEach
    void setUp() {
        try {
            creditCardsJdbcTemplate.execute("DROP TABLE IF EXISTS credit_card");
        } catch (Exception e) {
            // Table might not exist
        }
    }

    @Test
    void testSqlInjectionInCreditCardParameter() throws Exception {
        String maliciousInput = "1234'); DROP TABLE credit_card; --";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousInput)
                .param("shipmentId", shipmentId)
                .header("Accept", "application/json")
                .header("Connection", "keep-alive")
                .header("User-Agent", "Java/11.0.29"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].success").value(true));

        Integer tableCount = creditCardsJdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'credit_card'",
            Integer.class
        );
        
        assert tableCount != null && tableCount > 0 : "Table should still exist after SQL injection attempt";
    }

    @Test
    void testSqlInjectionInShipmentIdParameter() throws Exception {
        String creditCard = "4111111111111111";
        String maliciousShipmentId = "1 OR 1=1";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", maliciousShipmentId)
                .header("Accept", "application/json")
                .header("Connection", "keep-alive")
                .header("User-Agent", "Java/11.0.29"))
                .andExpect(status().isOk());

        Integer count = creditCardsJdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM credit_card WHERE card_number = ?",
            Integer.class,
            creditCard
        );
        
        assert count != null && count == 1 : "Only one record should be inserted";
    }

    @Test
    void testValidPaymentProcessing() throws Exception {
        String creditCard = "4111111111111111";
        String shipmentId = "123";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId)
                .header("Accept", "application/json")
                .header("Connection", "keep-alive")
                .header("User-Agent", "Java/11.0.29"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].success").value(true))
                .andExpect(jsonPath("$[0].shipment_id").value(shipmentId))
                .andExpect(jsonPath("$[0].credit_card").value("XXXX-XXXX-XXXX-1111"));
    }

    @Test
    void testMissingParameters() throws Exception {
        mockMvc.perform(get("/payments")
                .header("Accept", "application/json")
                .header("Connection", "keep-alive")
                .header("User-Agent", "Java/11.0.29"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").exists());
    }
}
