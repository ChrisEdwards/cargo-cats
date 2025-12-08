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
    void testSqlInjectionPrevention_creditCardParameter() throws Exception {
        String maliciousInput = "1234'); DROP TABLE credit_card; --";
        String shipmentId = "1";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousInput)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(maliciousInput),
                eq(shipmentId)
        );

        verify(creditCardsJdbcTemplate, never()).execute(anyString());
    }

    @Test
    void testSqlInjectionPrevention_shipmentIdParameter() throws Exception {
        String creditCard = "1234567890123456";
        String maliciousShipmentId = "1 OR 1=1; DROP TABLE shipment; --";

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
    void testParameterizedQueryUsage_normalInput() throws Exception {
        String creditCard = "4111111111111111";
        String shipmentId = "42";

        mockMvc.perform(get("/payments")
                .param("creditCard", creditCard)
                .param("shipmentId", shipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(creditCard),
                eq(shipmentId)
        );

        verify(jdbcTemplate).update(
                eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
                eq("XXXX-XXXX-XXXX-1111"),
                eq(shipmentId)
        );
    }

    @Test
    void testSqlInjectionPrevention_bothParametersMalicious() throws Exception {
        String maliciousCreditCard = "1234' OR '1'='1";
        String maliciousShipmentId = "1; DELETE FROM shipment WHERE 1=1; --";

        mockMvc.perform(get("/payments")
                .param("creditCard", maliciousCreditCard)
                .param("shipmentId", maliciousShipmentId))
                .andExpect(status().isOk());

        verify(creditCardsJdbcTemplate).update(
                eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
                eq(maliciousCreditCard),
                eq(maliciousShipmentId)
        );

        verify(jdbcTemplate).update(
                eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
                anyString(),
                eq(maliciousShipmentId)
        );
    }
}
