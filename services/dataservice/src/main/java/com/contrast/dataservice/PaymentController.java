package com.contrast.dataservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin(originPatterns = "*")
public class PaymentController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    @Autowired
    @Qualifier("creditCardsJdbcTemplate")
    private JdbcTemplate creditCardsJdbcTemplate;
    
    @GetMapping("/payments")
    public List<Map<String, Object>> executeRawQuery(
            @RequestParam(value = "creditCard", required = false) String creditCard,
            @RequestParam(value = "shipmentId", required = false) String shipmentId) {
        
        System.out.println("=== PAYMENT ENDPOINT REQUEST ===");
        System.out.println("Endpoint: /payments");
        System.out.println("Credit Card param: " + (creditCard != null ? creditCard : "null"));
        System.out.println("Shipment ID param: " + (shipmentId != null ? shipmentId : "null"));
        System.out.println("================================");
        
        try {
            List<Map<String, Object>> result = null;
            
            if (creditCard != null && !creditCard.isEmpty() && shipmentId != null && !shipmentId.isEmpty()) {
                // Create credit card table if it doesn't exist in the credit_cards database
                String createTableSql = "CREATE TABLE IF NOT EXISTS credit_card (" +
                    "id BIGINT AUTO_INCREMENT PRIMARY KEY, " +
                    "card_number VARCHAR(255) NOT NULL, " +
                    "shipment_id BIGINT NOT NULL)";
                creditCardsJdbcTemplate.execute(createTableSql);
                
                // Validate shipmentId is numeric to prevent SQL injection
                Long validatedShipmentId = validateShipmentId(shipmentId);
                
                // Insert credit card data using parameterized query
                String insertSql = "INSERT INTO credit_card (card_number, shipment_id) VALUES (?, ?)";
                System.out.println("DEBUG: Executing SQL statement: " + insertSql + " on credit_cards database");
                System.out.println("DEBUG: Credit Card parameter: " + creditCard);
                System.out.println("DEBUG: Shipment ID parameter: " + validatedShipmentId);
                
                System.out.println("DEBUG: Using creditCardsJdbcTemplate to execute query on credit_cards database");
                creditCardsJdbcTemplate.update(insertSql, creditCard, validatedShipmentId);
                
                // Mask credit card for display
                String maskedCard = maskCreditCard(creditCard);
                
                // Update the main shipment table using parameterized query
                String updateSql = "UPDATE shipment SET credit_card = ? WHERE id = ?";
                
                System.out.println("DEBUG: Using main jdbcTemplate to execute query on main database");
                
                jdbcTemplate.update(updateSql, maskedCard, validatedShipmentId);
                
                // Create response with success message
                result = List.of(Map.of(
                    "success", true,
                    "message", "Credit card stored in separate database for shipment",
                    "shipment_id", validatedShipmentId,
                    "credit_card", maskedCard
                ));
            } else {
                result = List.of(Map.of(
                    "error", true,
                    "message", "Both creditCard and shipmentId parameters are required for payment processing",
                    "credit_card_param", creditCard != null ? creditCard : "none",
                    "shipment_id_param", shipmentId != null ? shipmentId : "none"
                ));
            }
            
            return result;
        } catch (Exception e) {
            return List.of(Map.of(
                "error", true,
                "message", e.getMessage(),
                "type", e.getClass().getSimpleName(),
                "credit_card_param", creditCard != null ? creditCard : "none",
                "shipment_id_param", shipmentId != null ? shipmentId : "none"
            ));
        }
    }
    
    private Long validateShipmentId(String shipmentId) {
        try {
            return Long.parseLong(shipmentId);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid shipment ID format");
        }
    }
    
    private String maskCreditCard(String creditCard) {
        if (creditCard == null || creditCard.isEmpty()) {
            return "";
        }
        if (creditCard.length() <= 4) {
            return creditCard;
        }
        return "XXXX-XXXX-XXXX-" + creditCard.substring(creditCard.length() - 4);
    }
}
