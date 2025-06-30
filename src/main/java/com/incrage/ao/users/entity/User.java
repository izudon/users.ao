package com.incrage.ao.users.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @Column(name = "id", length = 6, nullable = false)
    private String id;

    @Column(name = "code_hash", columnDefinition = "BINARY(32)", nullable = false, unique = true)
    private byte[] codeHash;

    @Column(name = "lang", length = 16)
    private String lang;

    @Column(name = "birth_year")
    private Short birthYear;

    @Column(name = "handle_name", length = 10)
    private String handleName;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
