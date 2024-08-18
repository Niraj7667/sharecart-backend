import { nanoid } from 'nanoid';
import prisma from '../models/prismaClient.js';

export const createCart = async (req, res) => {
  const { name } = req.body;
  const userId = req.user.id;
  try{
  // Check if a cart with the given name and user already exists
  const existingCart = await prisma.cart.findFirst({
    where: {
      name,
      users: {
        some: {
          userId,
        },
      },
    },
  });

  // If the cart exists, return it
  if (existingCart) {
    return res.status(200).json({
      cartId: existingCart.id,
      invitationLink: existingCart.invitationLink,
    });
  }

  const cart = await prisma.cart.create({
    data: {
      name,
      invitationLink: nanoid(),
      users: {
        create: { userId },
      },
    },
  });

  // Return the new cart's ID and invitation link
  res.status(201).json({
    cartId: cart.id,
    invitationLink: cart.invitationLink,
  });
} catch (err) {
  console.error(err);
  res.status(500).json({ error: 'Failed to create cart' });
}

};

export const joinCart = async (req, res) => {
  const { invitationLink } = req.body;
  const userId = req.user.id;

  try{
   const cart = await prisma.cart.findUnique({
    where: { invitationLink },
    include: {
      users: {
        include: {
          user: true
        }
      }
    }
  });
  if (!cart) {
    return res.status(404).send('Cart not found');
  }

// Check if the user is the owner of the cart
const isOwner = cart.users.some(userCart => userCart.userId === userId);
if (isOwner) {
  return res.status(400).json({ message: 'You cannot join your own cart' });
}

  // Check if the user has already joined the cart
  const existingUserCart = await prisma.userCart.findFirst({
    where: {
      userId: userId,
      cartId: cart.id
    }
  });
  if (existingUserCart) {
    return res.status(400).json({ message: 'You have already joined this cart' });
  }

  await prisma.userCart.create({
    data: {
      userId,
      cartId: cart.id,
    },
  });
  const ownerName = cart.users[0]?.user?.name || 'Unknown';
  res.json({
    message: 'Joined cart successfully',
    cartId: cart.id,
    ownerName: ownerName
  })
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to join cart' });
  }
};

export const addProductToCart = async (req, res) => {
  const { cartId, productId } = req.body;

  const cartProduct = await prisma.cartProduct.create({
    data: {
      cartId,
      productId,
    },
  });

  res.status(201).json(cartProduct);
};


export const joinedCarts = async (req, res) => {
  try {
    const userId = req.user.id; // Get the user ID from the authenticated user

    const userCarts = await prisma.userCart.findMany({
      where: { userId },
      include: {
        cart: {
          include: {
            users: {
              include: {
                user: true
              }
            }
          }
        }
      }
    });

    const carts = userCarts.map((userCart) => {
      const ownerName = userCart.cart.users.length > 0 && userCart.cart.users[0].user
        ? userCart.cart.users[0].user.name
        : 'Unknown';

      return {
        cartId: userCart.cartId,
        ownerName,
        invitationLink: userCart.cart.invitationLink,
      };
    });

    res.json(carts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch joined carts' });
  }
};


// Fetch products in the shared cart by cartId
export const getSharedCartProducts = async (req, res) => {
  const { cartId } = req.params;

      if (!cartId) {
        return res.status(400).json({ error: "Cart ID is required." });
      }
  
  try {
    const cartProducts = await prisma.cartProduct.findMany({
      where: { cartId },
      include: { product: true },
    });
    res.json(cartProducts.map(cp => cp.product));
  } catch (error) {
    console.error('Error fetching shared cart products:', error);
    res.status(500).json({ error: 'Error fetching shared cart products' });
  }
};


export const allProducts =  async (req, res) => {
  try {
    const products = await prisma.product.findMany();
    res.json(products);
    
  } catch (error) {
    console.error('Error fetching products:', error);
    console.log(error);
    res.status(500).json({ error: 'Error fetching products' });
  }
};

export const addProductToSharedCart = async (req, res) => {
  const { productId } = req.body;
  const { cartId } = req.params; // Get cartId from the request parameters
  const userId = req.user.id; // Assuming user is authenticated and user ID is available

  try {
    // Check if the shared cart exists and the user is part of it
    const sharedCart = await prisma.cart.findFirst({
      where: { id: cartId },
      include: {
        users: {
          where: { id: userId }, // Check if the user is part of the shared cart
        },
      },
    });

    if (!sharedCart) {
      return res.status(404).json({ error: 'Shared cart not found or you do not have access to it' });
    }

    // Fetch the user's username
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { name: true }, // Select only the name field
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Add the product to the shared cart with the username
    await prisma.cartProduct.create({
      data: {
        cartId: sharedCart.id,
        productId,
        username: user.name, // Store the username who added the product
      },
    });

    res.json({ message: 'Product added to shared cart' });
  } catch (error) {
    console.error('Error adding product to shared cart:', error);
    res.status(500).json({ error: 'Error adding product to shared cart' });
  }
};





// Endpoint 2: Add a product to the user's cart
export const addtomain =  async (req, res) => {
  const { productId } = req.body;
  const userId = req.user.id; // Assuming user is authenticated and user ID is available

  try {
    let userCart = await prisma.userCart.findFirst({
      where: { userId },
      include: { cart: true },
    });

    if (!userCart) {
      const newCart = await prisma.cart.create({
        data: { name: `${req.user.name}'s Cart`, users: { create: { userId } } },
      });
      userCart = { cartId: newCart.id };
    }

    await prisma.cartProduct.create({
      data: {
        cartId: userCart.cartId,
        productId,
      },
    });

    res.json({ message: 'Product added to cart' });
  } catch (error) {
    console.error('Error adding product to cart:', error);
    res.status(500).json({ error: 'Error adding product to cart' });
  }
};


export const voteProduct = async (req, res) => {
  const { cartId, productId } = req.body;
  const userId = req.user.id;
  console.log(req.user.name);

  try {
    // Check if the user has already voted for this product in the cart
    const existingVote = await prisma.vote.findFirst({
      where: {
        userId,
        productId,
        cartId,
      },
    });

    if (existingVote) {
      return res.status(400).json({ error: "You have already voted for this product." });
    }

    // Create a new vote
    const vote = await prisma.vote.create({
      data: {
        cartId,
        productId,
        userId,
      },
    });

    // Increment the vote count for the product
    const updatedProduct = await prisma.product.update({
      where: { id: productId },
      data: {
        voteCount: {
          increment: 1,
        },
      },
    });

    res.status(201).json(updatedProduct);
  } catch (error) {
    console.error("Error voting for product:", error);  // Log the exact error
    res.status(500).json({ error: "An error occurred while voting." });
  }
};

export const deleteProduct = async (req, res) => {
  const { cartId, productId } = req.params; // Get cartId and productId from request parameters

  try {
    // Find the product in the cart based on cartId and productId
    const cartProduct = await prisma.cartProduct.findFirst({
      where: {
        cartId: cartId,
        productId: productId,
      },
      select: {
        id: true, // Select only the id field
      },
    });

    if (!cartProduct) {
      return res.status(404).json({ error: 'Product not found in cart' });
    }

    // Delete the product using the retrieved id
    await prisma.cartProduct.delete({
      where: {
        id: cartProduct.id,
      },
    });

    res.status(200).json({ message: 'Product removed from shared cart' });
  } catch (error) {
    console.error('Error removing product from shared cart:', error);
    res.status(500).json({ error: 'An error occurred while removing the product from the cart' });
  }
};
