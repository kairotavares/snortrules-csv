
RULES_URL=https://www.snort.org/downloads/community/snort3-community-rules.tar.gz

TARGET_DIR=target
DATASET_DIR=dataset

RULES_FILE=${TARGET_DIR}/snort3-community-rules/snort3-community.rules
OUTPUT_FILE=${DATASET_DIR}/comunnity-rules.csv

all: parse.csv

$(TARGET_DIR):
	mkdir -p ${TARGET_DIR}

$(DATASET_DIR):
	mkdir -p ${DATASET_DIR}

$(RULES_FILE): $(TARGET_DIR)
	curl -L "${RULES_URL}" | tar -xz -C ${TARGET_DIR}

parse.csv: $(DATASET_DIR)
	python3 snort_csv.py ${RULES_FILE} ${OUTPUT_FILE}