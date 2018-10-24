package main

func main() {
	a, err := newApp()
	if err != nil {
		panic(err)
	}

	err = a.run()
	if err != nil {
		panic(err)
	}
}
