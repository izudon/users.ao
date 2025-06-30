package com.incrage.ao.users.repository;

import com.incrage.ao.users.entity.Authentication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthenticationRepository
    extends JpaRepository<Authentication, UUID> {

    Optional<Authentication> findByRegistrationIdAndSubject
	(String registrationId, String subject);
}
