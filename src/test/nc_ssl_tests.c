#include <nc_ssl.h>

#define TEST_START printf("Running %s\n", __func__)
#define TEST_BUF_LEN 100 // over allocate to test out of bounds

static void
assert(int result, const char *msg) {
	if (result) {
		return;
	}

	printf("Failed assert: %s\n", msg);
	exit(1);
}

static void
test_copy_all_to_buffer__one_vector(void) {
	TEST_START;

	struct iovec iov[1];

	iov[0].iov_base = "first";
	iov[0].iov_len = 5;

	char outbuf[TEST_BUF_LEN] = { 0 };
	copy_all_to_buffer(outbuf, 5, iov, 1);

	assert(strncmp(outbuf, "first", 5) == 0, "Output buffer does not match input vectors.");

	char zerobuf[TEST_BUF_LEN] = { 0 };
	assert(memcmp(outbuf+5, zerobuf, TEST_BUF_LEN-5) == 0, "Output buffer wrote outside of buffer.");
}

static void
test_copy_all_to_buffer__three_vectors(void) {
	TEST_START;

	struct iovec iov[3];

	iov[0].iov_base = "first";
	iov[0].iov_len = 5;
	iov[1].iov_base = "second";
	iov[1].iov_len = 6;
	iov[2].iov_base = "third";
	iov[2].iov_len = 5;


	char outbuf[TEST_BUF_LEN] = { 0 };
	copy_all_to_buffer(outbuf, 16, iov, 3);

	assert(memcmp(outbuf, "firstsecondthird", 16) == 0, "Output buffer does not match input vectors.");

	char zerobuf[TEST_BUF_LEN] = { 0 };
	assert(memcmp(outbuf+16, zerobuf, TEST_BUF_LEN-16) == 0, "Output buffer wrote outside of buffer.");
}

static void
test_copy_all_to_buffer__empty_vector(void) {
	TEST_START;

	struct iovec iov[3];

	iov[0].iov_base = "";
	iov[0].iov_len = 0;


	char outbuf[TEST_BUF_LEN] = { 0 };
	copy_all_to_buffer(outbuf, 0, iov, 1);

	assert(memcmp(outbuf, "", 0) == 0, "Output buffer does not match input vectors.");

	char zerobuf[TEST_BUF_LEN] = { 0 };
	assert(memcmp(outbuf+0, zerobuf, TEST_BUF_LEN-0) == 0, "Output buffer wrote outside of buffer.");
}

static void
test_copy_all_to_buffer__some_empty_vectors(void) {
	TEST_START;

	struct iovec iov[3];

	iov[0].iov_base = "first";
	iov[0].iov_len = 5;
	iov[1].iov_base = "";
	iov[1].iov_len = 0;
	iov[2].iov_base = "third";
	iov[2].iov_len = 5;


	char outbuf[TEST_BUF_LEN] = { 0 };
	copy_all_to_buffer(outbuf, 10, iov, 3);

	assert(memcmp(outbuf, "firstthird", 10) == 0, "Output buffer does not match input vectors.");

	char zerobuf[TEST_BUF_LEN] = { 0 };
	assert(memcmp(outbuf+10, zerobuf, TEST_BUF_LEN-10) == 0, "Output buffer wrote outside of buffer.");
}


int
main(int argc, char **argv) {
	test_copy_all_to_buffer__one_vector();
	test_copy_all_to_buffer__three_vectors();
	test_copy_all_to_buffer__empty_vector();
	test_copy_all_to_buffer__some_empty_vectors();

	printf("All tests passed.\n");
}