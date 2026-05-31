package com.reimagineafrica.auth.event;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthEventPublisher {

    private final RabbitTemplate rabbitTemplate;
    private static final String EXCHANGE = "saccos.auth.events";

    public void publishPasswordResetOtp(String phone, String fullName, String otp) {
        publish("auth.password.reset.otp", Map.of(
                "phone", phone,
                "fullName", fullName,
                "otp", otp,
                "expiryMinutes", "15"
        ));
    }

    public void publishUserCreated(String phone, String fullName, String username, String tempPassword) {
        publish("auth.user.created", Map.of(
                "phone", phone,
                "fullName", fullName,
                "username", username,
                "temporaryPassword", tempPassword
        ));
    }

    private void publish(String routingKey, Map<String, String> payload) {
        try {
            rabbitTemplate.convertAndSend(EXCHANGE, routingKey, payload);
        } catch (Exception e) {
            log.error("Failed to publish {}: {}", routingKey, e.getMessage());
        }
    }
}
