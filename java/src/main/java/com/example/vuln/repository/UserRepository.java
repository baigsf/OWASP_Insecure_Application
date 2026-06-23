package com.example.vuln.repository;

import com.example.vuln.model.User;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.List;

@Repository
public class UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // VULNERABILITY: SQL Injection via concatenation
    @SuppressWarnings("unchecked")
    public List<User> findByUsernameUnsafe(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        return query.getResultList();
    }

    // VULNERABILITY: SQL Injection in LIKE clause
    @SuppressWarnings("unchecked")
    public List<User> searchUsersUnsafe(String term) {
        String sql = "SELECT * FROM users WHERE username LIKE '%" + term + "%'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        return query.getResultList();
    }

    // VULNERABILITY: SQL Injection in ORDER BY
    @SuppressWarnings("unchecked")
    public List<User> listUsersOrderedUnsafe(String column, String direction) {
        String sql = "SELECT * FROM users ORDER BY " + column + " " + direction;
        Query query = entityManager.createNativeQuery(sql, User.class);
        return query.getResultList();
    }

    // VULNERABILITY: SQL Injection in UPDATE
    public void updatePasswordUnsafe(String username, String newPassword) {
        String sql = "UPDATE users SET password = '" + newPassword + "' WHERE username = '" + username + "'";
        entityManager.createNativeQuery(sql).executeUpdate();
    }

    // VULNERABILITY: SQL Injection in INSERT
    public void createUserUnsafe(String username, String password, String role) {
        String sql = "INSERT INTO users (username, password, role) VALUES ('" + username + "', '" + password + "', '" + role + "')";
        entityManager.createNativeQuery(sql).executeUpdate();
    }

    // VULNERABILITY: SQL Injection in DELETE
    public void deleteUserUnsafe(String username) {
        String sql = "DELETE FROM users WHERE username = '" + username + "'";
        entityManager.createNativeQuery(sql).executeUpdate();
    }
}
