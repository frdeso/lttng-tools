volatile int not_a_function = 0;
void __attribute__ ((noinline))  test_function()
{
}
int main()
{
	test_function();
	return 0;
}
