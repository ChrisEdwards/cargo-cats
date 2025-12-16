package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    void testSqlInjectionAttemptInCreditCardParameter() throws Exception {
        String maliciousCreditCard = "1234'; DROP TABLE credit_card; --";
        String shipmentId = "1";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
            eq(maliciousCreditCard),
            eq(shipmentId)
        );
    }

    @Test
    void testSqlInjectionAttemptInShipmentIdParameter() throws Exception {
        String creditCard = "1234567890123456";
        String maliciousShipmentId = "1 OR 1=1";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
            eq(creditCard),
            eq(maliciousShipmentId)
        );

        verify(jdbcTemplate).update(
            eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
            anyString(),
            eq(maliciousShipmentId)
        );
    }

    @Test
    void testParameterizedQueriesUsedForInsert() throws Exception {
        String creditCard = "1234567890123456";
        String shipmentId = "42";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
            eq(creditCard),
            eq(shipmentId)
        );

        verify(creditCardsJdbcTemplate, never()).execute(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES ('" + creditCard + "', " + shipmentId + ")")
        );
    }

    @Test
    void testParameterizedQueriesUsedForUpdate() throws Exception {
        String creditCard = "1234567890123456";
        String shipmentId = "42";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        verify(jdbcTemplate).update(
            eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
            anyString(),
            eq(shipmentId)
        );

        verify(jdbcTemplate, never()).execute(anyString());
    }
}
