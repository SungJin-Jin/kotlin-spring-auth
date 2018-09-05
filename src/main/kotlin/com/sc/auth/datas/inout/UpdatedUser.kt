package com.sc.auth.datas.inout

import com.fasterxml.jackson.annotation.JsonRootName
import javax.validation.constraints.Pattern
import javax.validation.constraints.Size

@JsonRootName("user")
data class UpdatedUser(
        @Size(min = 1, message = "can't be empty")
        @Pattern(regexp = "^\\w+$", message = "must be alphanumeric")
        var username: String?,

        @Size(min = 1, message = "can't be empty")
        @Pattern(regexp = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}$", message = "must be a valid email")
        var email: String?,

        @Size(min = 8, message = "must be length more than 8")
        var password: String?,
        var image: String?,
        var bio: String?
)