package com.av.base.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.io.Serializable;
import java.util.Comparator;
import java.util.Date;
import java.util.Objects;
import java.util.function.Function;

@Getter
@Setter
@NoArgsConstructor
@MappedSuperclass
public class BaseEntity implements Serializable, Comparable<BaseEntity> {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "default_gen")
    private Long id;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @NotNull
    @CreatedDate
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @LastModifiedDate
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "updated_date")
    private Date updatedDate;

    @Column(name = "is_deleted", nullable = false)
    private boolean isDeleted = false;

    @Column(name = "is_enabled", nullable = false)
    private boolean isEnabled = true;

    @PrePersist
    public void prePersist() {
        this.createdDate = new Date();
        this.version = 0;
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedDate = new Date();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof BaseEntity that)) return false;
        return isDeleted() == that.isDeleted() && isEnabled() == that.isEnabled() && Objects.equals(getId(), that.getId()) && Objects.equals(getCreatedDate(), that.getCreatedDate()) && Objects.equals(getUpdatedDate(), that.getUpdatedDate());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(), getCreatedDate(), getUpdatedDate(), isDeleted(), isEnabled());
    }

    @Override
    public int compareTo(BaseEntity o) {
        if (Objects.isNull(o))
            return 1;
        return Objects.compare(
                this, o,
                BaseEntity.getComparator()
        );
    }

    public static <T extends BaseEntity> Comparator<T> getComparator() {
        Function<T, Long> function = T::getId;
        return (Comparator<T> & Serializable)
                (c1, c2) -> function.apply(c1).compareTo(function.apply(c2));
    }
}
