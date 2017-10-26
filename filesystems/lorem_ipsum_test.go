package filesystems

var loremIpsumStrs = []string{
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut molestie convallis enim in luctus. Proin sollicitudin congue vehicula. In eros risus, imperdiet id interdum vitae, iaculis id justo. Nullam rhoncus ultricies porta. Sed at varius sapien, a malesuada augue. Sed in accumsan magna Etiam ullamcorper eu ipsum in egestas. Morbi id tellus eros. Sed nec fermentum ante. In non dolor tellus. Nullam interdum porta faucibus. Ut id risus libero. Quisque nec justo at nisl egestas dictum a in libero. Aenean at bibendum felis.",
	"Suspendisse potenti. Vivamus condimentum viverra ipsum, id facilisis elit pulvinar vel. In posuere aliquet magna, quis ullamcorper odio vulputate eu. Pellentesque ut odio diam. Aliquam et velit non quam lobortis eleifend. Mauris interdum sit amet magna ac fermentum. Morbi in varius orci.",
	"Etiam vestibulum gravida purus, quis tempor magna dictum in. Mauris egestas consectetur sem, et consectetur leo dignissim nec. Ut ornare, enim elementum porttitor semper, mauris mi hendrerit metus, molestie pellentesque nulla magna sit amet magna. Aliquam ac nibh blandit, lacinia lorem non, commodo eros. Fusce in risus sem. Pellentesque auctor ipsum vel placerat semper. Nulla non magna sit amet enim porta tristique sit amet vel orci. Mauris ac metus aliquet, placerat lorem non, interdum leo. Donec sodales enim non tellus consequat, non bibendum elit tincidunt. Aenean id tempor massa, in pharetra odio. Vivamus tincidunt nisi sit amet risus vehicula, eget imperdiet diam ullamcorpe. Etiam condimentum cursus enim, sed dictum metus faucibus et. Vestibulum vitae est in elit tincidunt lacinia eu eget ligula.",
	"Curabitur commodo, est sed condimentum rutrum, massa libero dignissim dolor, nec dignissim turpis nunc eget neque. Nulla quis vestibulum eros, sit amet fermentum quam. Aliquam porttitor, purus ac feugiat ultricies, tortor dui facilisis odio, sed pellentesque risus ipsum eu eros. Pellentesque rutrum, velit quis fringilla blandit, mauris lorem interdum nibh, sit amet convallis orci risus et ante. In eget mi id nulla bibendum suscipit. Pellentesque rutrum velit nisi, non cursus eros hendrerit ut. Donec euismod tellus non augue ultricies, in gravida justo accumsan. Nulla eget magna ac odio cursus elementum. Phasellus risus magna, pharetra sit amet massa ac, fermentum pharetra ligula.",
	"Donec a nunc sed nisl lobortis dapibus vel non orci. Mauris dictum, sapien non interdum lacinia, sapien arcu maximus augue, vel sagittis metus mi sed nisl. Morbi sagittis tincidunt imperdiet. Integer non ante at ex congue maximus. Curabitur fringilla massa nec nunc faucibus lacinia. Fusce turpis elit, hendrerit ut varius sed, luctus at dui. Duis sit amet volutpat sapien, ut ultrices mi. Cras ut eleifend lacus. Quisque vel nisi faucibus, euismod lectus sed, congue mi. Vivamus suscipit ut nisi nec ornare. Sed non leo semper, semper urna non, vehicula nunc. Phasellus at odio nec lacus imperdiet semper sit amet a sapien",
}

var loremIpsum = [][]byte{}
var loremIpsumNoNewlines = [][]byte{}

func init() {
	for idx := range loremIpsumStrs {
		loremIpsum = append(loremIpsum, []byte(loremIpsumStrs[idx]+"\n"))
		loremIpsumNoNewlines = append(loremIpsumNoNewlines, []byte(loremIpsumStrs[idx]))
	}
}
