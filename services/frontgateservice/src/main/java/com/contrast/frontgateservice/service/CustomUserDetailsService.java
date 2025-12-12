package com.contrast.frontgateservice.service;

import com.contrast.frontgateservice.entity.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LogManager.getLogger(CustomUserDetailsService.class);

    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String sanitizedUsername = sanitizeForLogging(username);
        logger.info("Login attempt for user: {}", sanitizedUsername);
        
        User user = userService.findByUsername(username);
        if (user == null) {
            logger.error("Failed login attempt for non-existent user");
            throw new UsernameNotFoundException("User not found: " + sanitizeForLogging(username));
        }
        
        logger.info("Successful authentication for user: {}", sanitizedUsername);
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(new ArrayList<>())
                .disabled(!user.isEnabled())
                .build();
    }

    private String sanitizeForLogging(String input) {
        if (input == null) {
            return null;
        }
        return input.replaceAll("\\$\\{[^}]*\\}", "");
    }
}
