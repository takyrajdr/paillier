# ------------------------------------------------------------------------------
#   Internal include
#
include_directories(${paillier_SOURCE_DIR}/include ${paillier_SOURCE_DIR}/src)


# ------------------------------------------------------------------------------
#   External include & libs
#

# bigi library
set( BIGI_DIR bigi)
set( BIGI_PATH ${paillier_SOURCE_DIR}/../${BIGI_DIR} )
include_directories(${BIGI_PATH}/include)
link_directories(${BIGI_PATH}/lib)


# ------------------------------------------------------------------------------
#   Sources
#

# local sources
set(SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/paillier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rng.c
)

# subdirs
#   ---   empty   ---


# ------------------------------------------------------------------------------
#   Static library & Linking
#
add_library(paillier STATIC ${SRC})
