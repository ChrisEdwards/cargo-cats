package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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

    @MockBean
    @Qualifier("creditCardsJdbcTemplate")
    private JdbcTemplate creditCardsJdbcTemplate;

    @Test
    void testSqlInjectionPrevention_CreditCardParameter() throws Exception {
        String maliciousCreditCard = "1234'); DROP TABLE credit_card; --";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(maliciousCreditCard),
                eq(1L)
        );

        verify(creditCardsJdbcTemplate, never()).execute(contains("DROP TABLE"));
    }

    @Test
    void testSqlInjectionPrevention_ShipmentIdParameter() throws Exception {
        String creditCard = "4111111111111111";
        String maliciousShipmentId = "1 OR 1=1";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk());

        verify(jdbcTemplate, never()).execute(contains("OR 1=1"));
    }

    @Test
    void testSqlInjectionPrevention_MultipleInjectionAttempts() throws Exception {
        String maliciousCreditCard = "1234' UNION SELECT * FROM users --";
        String maliciousShipmentId = "1; DELETE FROM shipment; --";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate, never()).execute(contains("UNION"));
        verify(jdbcTemplate, never()).execute(contains("DELETE"));
    }

    @Test
    void testParameterizedQueryUsage_ValidInput() throws Exception {
        String creditCard = "4111111111111111";
        String shipmentId = "123";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(creditCard),
                eq(123L)
        );

        verify(jdbcTemplate).update(
                eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
                startsWith("XXXX-XXXX-XXXX-"),
                eq(123L)
        );
    }

    @Test
    void testMissingParameters_NoCreditCard() throws Exception {
        mockMvc.perform(get("/payments")
                .param("shipmentId", "123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }

    @Test
    void testMissingParameters_NoShipmentId() throws Exception {
        mockMvc.perform(get("/payments")
                .param("creditCard", "4111111111111111"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }
}
