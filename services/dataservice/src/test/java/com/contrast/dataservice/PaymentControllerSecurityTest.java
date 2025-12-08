package com.contrast.dataservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class PaymentControllerSecurityTest {

    @Autowired
    private PaymentController paymentController;

    @MockBean
    private JdbcTemplate jdbcTemplate;

    @MockBean
    @Qualifier("creditCardsJdbcTemplate")
    private JdbcTemplate creditCardsJdbcTemplate;

    @Test
    void testSqlInjectionPrevention_CreditCardParameter() {
        String maliciousInput = "1234'); DROP TABLE credit_card; --";
        String validShipmentId = "123";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        List<Map<String, Object>> result = paymentController.executeRawQuery(maliciousInput, validShipmentId);

        verify(creditCardsJdbcTemplate).update(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
            eq(maliciousInput),
            eq(validShipmentId)
        );

        verify(jdbcTemplate).update(
            eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
            anyString(),
            eq(validShipmentId)
        );

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertTrue((Boolean) result.get(0).get("success"));
    }

    @Test
    void testSqlInjectionPrevention_ShipmentIdParameter() {
        String validCreditCard = "4111111111111111";
        String maliciousShipmentId = "1 OR 1=1; DROP TABLE shipment; --";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        List<Map<String, Object>> result = paymentController.executeRawQuery(validCreditCard, maliciousShipmentId);

        verify(creditCardsJdbcTemplate).update(
            eq("INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)"),
            eq(validCreditCard),
            eq(maliciousShipmentId)
        );

        verify(jdbcTemplate).update(
            eq("UPDATE shipment SET credit_card = ? WHERE id = ?"),
            anyString(),
            eq(maliciousShipmentId)
        );

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertTrue((Boolean) result.get(0).get("success"));
    }

    @Test
    void testSqlInjectionPrevention_BothParameters() {
        String maliciousCreditCard = "1234' OR '1'='1";
        String maliciousShipmentId = "1' OR '1'='1";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        List<Map<String, Object>> result = paymentController.executeRawQuery(maliciousCreditCard, maliciousShipmentId);

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

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertTrue((Boolean) result.get(0).get("success"));
    }

    @Test
    void testParameterizedQueriesUsed() {
        String creditCard = "4111111111111111";
        String shipmentId = "123";

        when(creditCardsJdbcTemplate.update(anyString(), any(), any())).thenReturn(1);
        when(jdbcTemplate.update(anyString(), any(), any())).thenReturn(1);

        paymentController.executeRawQuery(creditCard, shipmentId);

        verify(creditCardsJdbcTemplate).update(
            contains("?"),
            eq(creditCard),
            eq(shipmentId)
        );

        verify(jdbcTemplate).update(
            contains("?"),
            anyString(),
            eq(shipmentId)
        );
    }

    @Test
    void testMissingParameters() {
        List<Map<String, Object>> result = paymentController.executeRawQuery(null, null);

        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertTrue((Boolean) result.get(0).get("error"));
        assertEquals("Both creditCard and shipmentId parameters are required for payment processing", 
                     result.get(0).get("message"));

        verify(creditCardsJdbcTemplate, never()).update(anyString(), any(), any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any());
    }
}
