package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private DataServiceProxy dataServiceProxy;

    private User testUser;

    @BeforeEach
    public void setup() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("password");
        testUser.setEnabled(true);

        when(userService.findByUsername("testuser")).thenReturn(testUser);
        when(dataServiceProxy.createAddress(any())).thenReturn(
            ResponseEntity.status(HttpStatus.CREATED).body("{\"id\":1}")
        );
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithValidData_ShouldSucceed() throws Exception {
        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("fname", "John");
        address.put("name", "Doe");
        address.put("address", "123 Main St");
        addresses.add(address);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(addresses);
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
            "file",
            "addresses.ser",
            "application/octet-stream",
            baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                .file(file)
                .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithMaliciousPayload_ShouldReject() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new MaliciousClass());
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
            "file",
            "malicious.ser",
            "application/octet-stream",
            baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                .file(file)
                .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid or unsafe file content"));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithEmptyFile_ShouldReturnBadRequest() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "empty.ser",
            "application/octet-stream",
            new byte[0]
        );

        mockMvc.perform(multipart("/api/addresses/import")
                .file(file)
                .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("No file provided"));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithInvalidFormat_ShouldReturnBadRequest() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject("Not a list");
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
            "file",
            "invalid.ser",
            "application/octet-stream",
            baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                .file(file)
                .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid file format"));
    }

    private static class MaliciousClass implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        
        private void readObject(java.io.ObjectInputStream in) throws Exception {
            in.defaultReadObject();
        }
    }
}
