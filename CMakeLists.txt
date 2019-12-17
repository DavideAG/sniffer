PROJECT(sniffer)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

# Set source files
SET(SOURCES
	src/main.cpp
	src/packetcapture.cpp
)


# Default directories for include files
IF(WIN32)
	INCLUDE_DIRECTORIES (
		${SNIFFER_SOURCE_DIR}
		${SNIFFER_SOURCE_DIR}/../WPdPack/Include
	)
ELSE(WIN32)
	INCLUDE_DIRECTORIES (
		${SNIFFER_SOURCE_DIR}
	)
ENDIF(WIN32)


# Default directories for linking
#   (in Linux those are already in the system path)
IF(WIN32)
	LINK_DIRECTORIES(${SNIFFER_SOURCE_DIR}/../WPdPack/Lib)
ENDIF(WIN32)


# Platform-specific definitions
IF(WIN32)
	ADD_DEFINITIONS(
		-D_CRT_SECURE_NO_WARNINGS
		-D_CRT_SECURE_NO_DEPRECATE
		-DWIN32_LEAN_AND_MEAN
	)
ENDIF(WIN32)


# Create executable
ADD_EXECUTABLE(
	sniffer
	${SOURCES}
)


# Link the executable to the required libraries
IF(WIN32)
	TARGET_LINK_LIBRARIES(
		sniffer
		wpcap
		ws2_32
	)
ELSE(WIN32)
	TARGET_LINK_LIBRARIES(
		sniffer
		pcap
	)
ENDIF(WIN32)
