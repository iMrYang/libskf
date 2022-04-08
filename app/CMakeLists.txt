# output
set(APP_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/bin/)

# source files
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/   CPROJECT_APP_SOURCE_FILES)

# add suffix
set(APP_USE_SUFFIX  OFF)
if (${CPROJECT_BUILD_CPROJECT_SHARED_LIBS} AND ${CPROJECT_BUILD_CPROJECT_STATIC_LIBS})
  set(APP_USE_SUFFIX  ON)
endif()

# shared library test
if (CPROJECT_BUILD_CPROJECT_SHARED_LIBS)
  # add test
  foreach(_app_file ${CPROJECT_APP_SOURCE_FILES})
    # retrieve file name
    STRING(REGEX REPLACE ".+/(.+)\\..*" "\\1" _app_file_name ${_app_file})
    # rename
    if (APP_USE_SUFFIX)
      set(_app_file_name ${_app_file_name}_shared)
    endif()
    # exec
    add_executable(${_app_file_name} ${_app_file})
    # add depends
    add_dependencies(${_app_file_name} ${CPROJECT_SHARED_LIBRARY})
    # include library
    target_include_directories(${_app_file_name} PUBLIC ${CPROJECT_ISEC_INCLUDE_DIRECTORY})
    # link library
    target_link_libraries(${_app_file_name} ${CPROJECT_SHARED_LIBRARY})
    # set target
    set_target_properties(${_app_file_name} PROPERTIES
      ARCHIVE_OUTPUT_DIRECTORY "${APP_OUTPUT_DIRECTORY}"
      LIBRARY_OUTPUT_DIRECTORY "${APP_OUTPUT_DIRECTORY}"
      RUNTIME_OUTPUT_DIRECTORY "${APP_OUTPUT_DIRECTORY}"
      CLEAN_DIRECT_OUTPUT 1
    )
    # copy shared library
    if (MSVC)
      add_custom_command(TARGET ${_app_file_name} POST_BUILD
        # copy library to target directory
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CPROJECT_SHARED_LIBRARY_FILE} ${APP_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/
        # copy all out
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${APP_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/ ${APP_OUTPUT_DIRECTORY}/
      )
    endif()
    # install
    install(TARGETS ${_app_file_name} DESTINATION bin)
  endforeach()
endif()

# static library test
if (CPROJECT_BUILD_CPROJECT_STATIC_LIBS)
  # add test
  foreach(_app_file ${CPROJECT_APP_SOURCE_FILES})
    # retrieve file name
    STRING(REGEX REPLACE ".+/(.+)\\..*" "\\1" _app_file_name ${_app_file})
    # rename
    if (APP_USE_SUFFIX)
      set(_app_file_name ${_app_file_name}_static)
    endif()
    # add exec
    add_executable(${_app_file_name} ${_app_file})
    # add depends
    add_dependencies(${_app_file_name} ${CPROJECT_STATIC_LIBRARY})
    # link library
    target_link_libraries(${_app_file_name} ${CPROJECT_STATIC_LIBRARY})
    # install
    install(TARGETS ${_app_file_name} DESTINATION bin)
  endforeach()
endif()
