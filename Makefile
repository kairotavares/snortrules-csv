
RULES_URL=https://www.snort.org/downloads/community/snort3-community-rules.tar.gz

TARGET_DIR=target
DATASET_DIR=dataset

COMMUNITY_RULES_FILE=${TARGET_DIR}/snort3-community-rules/snort3-community.rules
COMMUNITY_OUTPUT_FILE=${DATASET_DIR}/comunnity-rules.csv

# Improve registered download
REGISTERED_RULES_FILE=${TARGET_DIR}/rules
REGISTERED_OUTPUT_FILE=${DATASET_DIR}/registered-rules.csv

all: parse.csv

$(TARGET_DIR):
	mkdir -p ${TARGET_DIR}

$(DATASET_DIR):
	mkdir -p ${DATASET_DIR}

$(COMMUNITY_RULES_FILE): $(TARGET_DIR)
	curl -L "${RULES_URL}" | tar -xz -C ${TARGET_DIR}

parse.csv.community: $(DATASET_DIR)
	python3 snort_csv.py ${COMMUNITY_RULES_FILE} ${COMMUNITY_OUTPUT_FILE}

parse.csv.registered: $(DATASET_DIR)
	python3 snort_csv.py ${REGISTERED_RULES_FILE} ${REGISTERED_OUTPUT_FILE}

