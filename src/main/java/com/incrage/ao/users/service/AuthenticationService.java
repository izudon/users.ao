package com.incrage.ao.users.service;

import com.incrage.ao.users.entity.Authentication;
import com.incrage.ao.users.repository.AuthenticationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
public class AuthenticationService {
    private static final Logger logger
	= LoggerFactory.getLogger(AuthenticationService.class);

    private AuthenticationRepository authRepository;

    @Autowired
    public AuthenticationService(AuthenticationRepository authRepository) {
        this.authRepository = authRepository;
    }

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public Authentication findOrSave(Authentication auth) {
        int retry = 5;

        // find
        Optional<Authentication> authOptional
	    = authRepository.findByRegistrationIdAndSubject(
		auth.getRegistrationId(),
		auth.getSubject());
        if (authOptional.isPresent())
            return authOptional.get();

        // save
        while (retry-- > 0) {
            auth.setId(UUID.randomUUID());
            try {
                authRepository.saveAndFlush(auth);
                return auth;
            } catch (DataIntegrityViolationException e) {
		// DuplicateKeyException の親クラス（JDBCでなくJPA）
                logger.info("Duplicate ID, retrying... remaining: "
			    + (retry + 1), e);
            }
        }
        throw new IllegalStateException(
	    "Failed to save Authentication after retries");
    }

    public Authentication findOrSave(String registrationId, String subject) {
	Authentication auth = new Authentication();
	auth.setRegistrationId(registrationId);
	auth.setSubject(subject);
	return findOrSave(auth);
    }
}
