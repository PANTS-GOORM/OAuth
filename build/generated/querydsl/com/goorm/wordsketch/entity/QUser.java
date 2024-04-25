package com.goorm.wordsketch.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QUser is a Querydsl query type for User
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QUser extends EntityPathBase<User> {

    private static final long serialVersionUID = -1690993641L;

    public static final QUser user = new QUser("user");

    public final DateTimePath<java.sql.Timestamp> createdDate = createDateTime("createdDate", java.sql.Timestamp.class);

    public final StringPath email = createString("email");

    public final NumberPath<Long> id = createNumber("id", Long.class);

    public final BooleanPath isAdmin = createBoolean("isAdmin");

    public final DateTimePath<java.sql.Timestamp> lastModifiedDate = createDateTime("lastModifiedDate", java.sql.Timestamp.class);

    public final StringPath nickname = createString("nickname");

    public final StringPath profileImg = createString("profileImg");

    public final StringPath refreshToken = createString("refreshToken");

    public final EnumPath<UserRole> role = createEnum("role", UserRole.class);

    public final EnumPath<UserSocialType> socialType = createEnum("socialType", UserSocialType.class);

    public QUser(String variable) {
        super(User.class, forVariable(variable));
    }

    public QUser(Path<? extends User> path) {
        super(path.getType(), path.getMetadata());
    }

    public QUser(PathMetadata metadata) {
        super(User.class, metadata);
    }

}

