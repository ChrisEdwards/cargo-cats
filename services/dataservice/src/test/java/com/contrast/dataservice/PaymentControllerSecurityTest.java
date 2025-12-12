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
    void testSqlInjectionPrevention_MaliciousShipmentId() throws Exception {
        String maliciousShipmentId = "1 OR 1=1";
        String creditCard = "1234567890123456";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }

    @Test
    void testSqlInjectionPrevention_MaliciousCreditCard() throws Exception {
        String maliciousCreditCard = "1234'); DROP TABLE credit_card; --";
        String shipmentId = "123";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].success").value(true));

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(maliciousCreditCard),
                eq(123L)
        );
    }

    @Test
    void testValidInput_ParameterizedQueryUsed() throws Exception {
        String creditCard = "1234567890123456";
        String shipmentId = "456";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].success").value(true))
                .andExpect(jsonPath("$[0].shipment_id").value(456));

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(creditCard),
                eq(456L)
        );
        verify(jdbcTemplate).update(
                eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
                eq("XXXX-XXXX-XXXX-3456"),
                eq(456L)
        );
    }

    @Test
    void testInvalidShipmentId_NonNumeric() throws Exception {
        String creditCard = "1234567890123456";
        String shipmentId = "abc123";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }

    @Test
    void testInvalidShipmentId_SqlInjectionAttempt() throws Exception {
        String creditCard = "1234567890123456";
        String shipmentId = "1; DELETE FROM shipment; --";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].error").value(true))
                .andExpect(jsonPath("$[0].message").value("Invalid shipment ID format"));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }
}
