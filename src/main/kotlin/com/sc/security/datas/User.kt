package com.sc.security.datas

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonRootName
import javax.persistence.*


@Entity
@JsonRootName("user")
data class User(
        @Id @GeneratedValue(strategy = GenerationType.AUTO)
        var id: Long = 0,
        var email: String = "",
        @JsonIgnore var password: String = "",
        var token: String = "",
        var username: String = "",
        var bio: String = "",
        var image: String = "",
        @ManyToMany @JsonIgnore
        var followes: List<User> = mutableListOf()
) {
    override fun toString(): String = "User($email, $username)"
}