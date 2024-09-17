package com.av.app.user.entity;

import com.av.base.entity.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity(name = User.ENTITY_NAME)
@Setter
@Getter
@Table(name = User.TABLE_NAME
        , uniqueConstraints = @UniqueConstraint
        (
                name = "uk_" + User.TABLE_NAME + "_username",
                columnNames = "username"
        )
)
@NoArgsConstructor
@SequenceGenerator(name = "default_gen", sequenceName = User.TABLE_NAME + "_seq", allocationSize = 1)
public class User extends BaseEntity implements UserDetails {

    public final static String TABLE_NAME = "users";
    public final static String ENTITY_NAME = "Users";

    @NotNull
    @Column(name = "username", unique = true, nullable = false, updatable = false)
    private String username;

    @NotNull
    @Column(name = "password")
    private String password;

    @ElementCollection(targetClass = UserRole.class, fetch = FetchType.EAGER)
    @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id", nullable = false))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Set<UserRole> roles;

    private void validateRoles() {
        if (roles == null) {
            roles = new HashSet<>(2);
        }
    }

    public void addRole(UserRole role) {
        validateRoles();
        roles.add(role);
    }

    public void addRoles(Collection<UserRole> collection) {
        validateRoles();
        roles.addAll(collection);
    }

    @Transient
    private transient Set<? extends GrantedAuthority> authorities = new HashSet<>();

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = new HashSet<>(authorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;
        if (!super.equals(o)) return false;
        return Objects.equals(getUsername(), user.getUsername()) && Objects.equals(getPassword(), user.getPassword()) && Objects.equals(getRoles(), user.getRoles()) && Objects.equals(getAuthorities(), user.getAuthorities());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getUsername(), getPassword(), getRoles(), getAuthorities());
    }
}
