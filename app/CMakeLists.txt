# Sources
set (APP_SOURCES "main.cpp")

# Executable
add_executable(${MAIN} ${APP_SOURCES})

target_link_libraries(${MAIN} PUBLIC jwt-cpp ${OPENSSL_LIBRARIES})
