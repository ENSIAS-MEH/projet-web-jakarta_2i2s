package com.secbret.controller;

import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.ScanJobRepository;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.ScanExecutor;
import com.secbret.service.ScanPersistence;
import jakarta.mvc.Models;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for ScanWebController's HTMX polling fragment (Part II §3 / Part V §1.2).
 *
 * <h2>Rules under test</h2>
 * <ul>
 *   <li>GET /scan/status/{jobId} for a terminal state (COMPLETED, FAILED, SUPERSEDED)
 *       MUST set HX-Trigger: stopPolling in the response header.</li>
 *   <li>GET /scan/status/{jobId} for a non-terminal state (PENDING, RUNNING)
 *       MUST NOT set HX-Trigger: stopPolling.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("ScanWebController HTMX stopPolling header")
class ScanWebControllerStopPollingTest {

    @Mock
    private ScanJobRepository scanJobRepository;
    @Mock
    private ScanResultRepository scanResultRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ScanPersistence scanPersistence;
    @Mock
    private ScanExecutor scanExecutor;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse httpResponse;

    /** Minimal in-memory Models implementation for testing. */
    private final Map<String, Object> modelMap = new HashMap<>();
    private final Models models = new Models() {
        @Override public Models put(String name, Object value) { modelMap.put(name, value); return this; }
        @Override public Object get(String name) { return modelMap.get(name); }
        @Override public <T> T get(String name, Class<T> type) { return type.cast(modelMap.get(name)); }
        @Override public Map<String, Object> asMap() { return modelMap; }
        @Override public java.util.Iterator<String> iterator() { return modelMap.keySet().iterator(); }
    };

    @InjectMocks
    private ScanWebController controller;

    private final UUID adminUserId = UUID.randomUUID();
    private final UUID jobId = UUID.randomUUID();

    @BeforeEach
    void setUp() throws Exception {
        // Inject the Models mock via reflection (CDI @Inject field)
        java.lang.reflect.Field modelsField = ScanWebController.class.getDeclaredField("models");
        modelsField.setAccessible(true);
        modelsField.set(controller, models);

        // Inject httpResponse via reflection
        java.lang.reflect.Field respField = ScanWebController.class.getDeclaredField("httpResponse");
        respField.setAccessible(true);
        respField.set(controller, httpResponse);

        // Inject request via reflection
        java.lang.reflect.Field reqField = ScanWebController.class.getDeclaredField("request");
        reqField.setAccessible(true);
        reqField.set(controller, request);

        // Stub as ADMIN (no ownership check)
        when(request.isUserInRole("ADMIN")).thenReturn(true);
        when(request.isUserInRole("ANALYST")).thenReturn(false);
        when(request.isUserInRole("REPORTER")).thenReturn(false);

        Principal principal = () -> "admin";
        when(request.getUserPrincipal()).thenReturn(principal);
        SecBretUser admin = new SecBretUser();
        admin.setUsername("admin");
        admin.setRole(UserRole.ADMIN);
        java.lang.reflect.Field idField = SecBretUser.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(admin, adminUserId);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(admin));
    }

    @ParameterizedTest(name = "status={0} → HX-Trigger: stopPolling MUST be set")
    @EnumSource(value = ScanJobStatus.class, names = {"COMPLETED", "FAILED", "SUPERSEDED"})
    @DisplayName("Terminal statuses trigger HX-Trigger: stopPolling")
    void terminalStatus_setsStopPollingHeader(ScanJobStatus status) {
        ScanJob job = buildJob(status);
        when(scanJobRepository.findByIdEager(jobId)).thenReturn(Optional.of(job));
        if (status == ScanJobStatus.COMPLETED) {
            when(scanResultRepository.findByScanJobId(any())).thenReturn(Optional.empty());
        }

        String view = controller.statusFragment(jobId);

        verify(httpResponse).setHeader("HX-Trigger", "stopPolling");
        assertThat(view).isEqualTo("/WEB-INF/views/scan/status-fragment.jsp");
        assertThat(modelMap.get("isTerminal")).isEqualTo(true);
    }

    @ParameterizedTest(name = "status={0} → HX-Trigger: stopPolling MUST NOT be set")
    @EnumSource(value = ScanJobStatus.class, names = {"PENDING", "RUNNING"})
    @DisplayName("Non-terminal statuses do NOT set HX-Trigger: stopPolling")
    void nonTerminalStatus_doesNotSetStopPollingHeader(ScanJobStatus status) {
        ScanJob job = buildJob(status);
        when(scanJobRepository.findByIdEager(jobId)).thenReturn(Optional.of(job));

        String view = controller.statusFragment(jobId);

        verify(httpResponse, never()).setHeader(any(), any());
        assertThat(view).isEqualTo("/WEB-INF/views/scan/status-fragment.jsp");
        assertThat(modelMap.get("isTerminal")).isEqualTo(false);
    }

    private ScanJob buildJob(ScanJobStatus status) {
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://example.test/polled");
        ScanJob j = new ScanJob();
        j.setUrl(url);
        j.setScanDepth(ScanDepth.QUICK);
        j.setStatus(status);
        return j;
    }
}
