package_add_test(test-recipe test-recipe.cpp lib-seeded)

target_include_directories(
    test-recipe
        PRIVATE
        ${PROJECT_SOURCE_DIR}/lib-seeded
        ${PROJECT_SOURCE_DIR}/extern/libsodium/src/libsodium/include
)

package_add_test(test-crypto test-crypto.cpp lib-seeded)

target_include_directories(
    test-crypto
        PRIVATE
        ${PROJECT_SOURCE_DIR}/lib-seeded
        ${PROJECT_SOURCE_DIR}/extern/libsodium/src/libsodium/include
)

package_add_test(test-key-formats test-key-formats.cpp lib-seeded)

target_include_directories(
    test-key-formats
        PRIVATE
        ${PROJECT_SOURCE_DIR}/lib-seeded
        ${PROJECT_SOURCE_DIR}/extern/libsodium/src/libsodium/include
)

