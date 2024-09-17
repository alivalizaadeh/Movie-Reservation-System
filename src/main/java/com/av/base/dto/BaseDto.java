package com.av.base.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
public class BaseDto {

    private Long id;

    private Long version;

    private Date createdDate;

    private Date updatedDate;

    private Boolean isDeleted = false;

    private Boolean isEnabled = true;
}
