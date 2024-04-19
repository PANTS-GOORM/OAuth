FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

COPY build/libs/*.jar app.jar
COPY src/main/resources/application-prod.yml application-prod.yml

ENV SPRING_PROFILES_ACTIVE=prod
ENTRYPOINT ["java","-jar","app.jar", "--spring.config.location=classpath:/application.yml,file:/app/application-prod.yml"]
