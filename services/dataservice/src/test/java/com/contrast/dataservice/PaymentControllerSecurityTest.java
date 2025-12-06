package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class PaymentControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JdbcTemplate jdbcTemplate;

    @MockBean(name = "creditCardsJdbcTemplate")
    private JdbcTemplate creditCardsJdbcTemplate;

    @Test
    void testSqlInjectionPrevention_creditCardParameter() throws Exception {
        String maliciousInput = "1234'; DROP TABLE credit_card; --";
        String validShipmentId = "123";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousInput)
                .param("shipmentId", validShipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(maliciousInput),
                eq(123L)
        );

        verify(creditCardsJdbcTemplate, never()).execute(contains("DROP TABLE"));
    }

    @Test
    void testSqlInjectionPrevention_shipmentIdParameter() throws Exception {
        String validCreditCard = "4111111111111111";
        String maliciousShipmentId = "123 OR 1=1";

        mockMvc.perform(get("/payments")
                .param("creditCard", validCreditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }

    @Test
    void testSqlInjectionPrevention_shipmentIdWithSqlKeywords() throws Exception {
        String validCreditCard = "4111111111111111";
        String maliciousShipmentId = "1; DELETE FROM shipment WHERE 1=1; --";

        mockMvc.perform(get("/payments")
                .param("creditCard", validCreditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }

    @Test
    void testValidInput_usesParameterizedQueries() throws Exception {
        String validCreditCard = "4111111111111111";
        String validShipmentId = "456";

        mockMvc.perform(get("/payments")
                .param("creditCard", validCreditCard)
                .param("shipmentId", validShipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(validCreditCard),
                eq(456L)
        );

        verify(jdbcTemplate).update(
                eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
                eq("XXXX-XXXX-XXXX-1111"),
                eq(456L)
        );
    }

    @Test
    void testCreditCardMasking() throws Exception {
        String validCreditCard = "4111111111111111";
        String validShipmentId = "789";

        mockMvc.perform(get("/payments")
                .param("creditCard", validCreditCard)
                .param("shipmentId", validShipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].credit_card").value("XXXX-XXXX-XXXX-1111"));
    }
}
