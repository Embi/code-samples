#include <iostream>
#include <fstream>
#include <vector>

// Implementation of a matrix container
template<typename T>
class Matrix
{
public:

  // Iterators
  // ---------------------------------------------------------------------------

  typedef typename std::vector<T>::iterator hiterator;
  typedef typename std::vector<T>::const_iterator const_hiterator;

  struct viterator
  {
    typename std::vector<std::vector<T> >::iterator row_it;
    std::size_t column;

    viterator operator++()
    {
      viterator tmp;
      tmp.row_it = ++row_it;
      tmp.column = column;
      return tmp;
    }

    viterator operator++(int)
    {
      viterator tmp;
      tmp.row_it = row_it;
      tmp.column = column;
      row_it++;
      return tmp;
    }

    T& operator*()
    {
      return (*row_it)[column];
    }

    typename std::vector<T>::iterator operator->()
    {
      return ((*row_it).begin() + column);
    }

    bool operator==(const viterator & other)
    {
      if ((row_it == other.row_it) && (column == other.column)) return true;
      else return false;
    }

    bool operator!=(const viterator & other)
    {
      if ((row_it != other.row_it) || (column != other.column)) return true;
      else return false;
    }
  };

  struct const_viterator
  {
    typename std::vector<std::vector<T> >::const_iterator row_it;
    std::size_t column;

    const_viterator operator++()
    {
      const_viterator tmp;
      tmp.row_it = ++row_it;
      tmp.column = column;
    }

    const_viterator operator++(int)
    {
      const_viterator tmp;
      tmp.row_it = row_it;
      tmp.column = column;
      row_it++;
      return tmp;
    }

    const T& operator*()
    {
      return (*row_it)[column];
    }

    typename std::vector<T>::const_iterator operator->()
    {
      return ((*row_it).cbegin() + column);
    }

    bool operator==(const const_viterator & other)
    {
      if ((row_it == other.row_it) && (column == other.column)) return true;
      else return false;
    }

    bool operator!=(const const_viterator & other)
    {
      if ((row_it != other.row_it) || (column != other.column)) return true;
      else return false;
    }
  };

  // Matrix constructors
  // ----------------------------------------------------------------------------

  explicit Matrix(const std::string& fileName)
  {

    std::ifstream matrixFile(fileName);
    matrixFile >> Width_;
    matrixFile >> Height_;

    // (Height_ + 1): add one additional line because of v_end()
    Matrix_.resize(Height_ + 1);
    for (std::size_t i = 0; i <= Height_; i++) {
      Matrix_[i].resize(Width_,T());
    }

    for (std::size_t i = 0; i < Height_; i++) {
      for (std::size_t j = 0; j < Width_; j++) {
        matrixFile >> Matrix_[i][j];
      }
    }
    matrixFile.close();

  }


  Matrix(std::size_t width, std::size_t height): Width_(width), Height_(height)
  {
    // (Height_ + 1): add one additional line because of v_end()
    Matrix_.resize(Height_ + 1);
    for (std::size_t i = 0; i <= Height_; i++) {
      Matrix_[i].resize(Width_,T());
    }
  }


  // Matrix element access
  // ---------------------------------------------------------------------------

  viterator v_begin(std::size_t column)
  {
    viterator tmp;
    tmp.column = column;
    tmp.row_it = Matrix_.begin();
    return tmp;
  }

  viterator v_end(std::size_t column)
  {
    viterator tmp;
    tmp.column = column;
    tmp.row_it = Matrix_.end() -1;
    return tmp;
  }

  hiterator h_begin(std::size_t row) { return Matrix_[row].begin();}
  hiterator h_end(std::size_t row) { return Matrix_[row].end();}
  T& GetElement(std::size_t x, std::size_t y) { return Matrix_[y][x];}

  // constat variants:

  const_viterator v_begin(std::size_t column) const
  {
    const_viterator tmp;
    tmp.column = column;
    tmp.row_it = Matrix_.cbegin();
    return tmp;
  }

  const_viterator v_end(std::size_t column) const
  {
    const_viterator tmp;
    tmp.column = column;
    tmp.row_it = Matrix_.cend() -1;
    return tmp;
  }

  const_hiterator h_begin(std::size_t row) const { return Matrix_[row].cbegin();}
  const_hiterator h_end(std::size_t row) const { return Matrix_[row].cend();}
    const T& GetElement(std::size_t x, std::size_t y) const { return (Matrix_[y][x]);}

  std::size_t width() const { return Width_; }
  std::size_t height() const { return Height_; }

  // implement matrix push_back operations:

  void h_push_back(T* values)
  {

      for(int i = 0; i < Height_; i++)
      {
          Matrix_[i].reserve(Width_ + 1);
          Matrix_[i].push_back(values[i]);
      }

      Matrix_[Height_].reserve(Width_ + 1);
      Matrix_[Height_].push_back(T());
      Width_++;

  }

  void v_push_back(T* values)
  {
      std::vector<T> tmp(10,T());

      for(int i = 0; i < Width_; i++)
      {
          Matrix_[Height_][i] = values[i];
      }

      Matrix_.reserve(Height_ + 2);
      Matrix_.push_back(tmp);
      Height_++;

  }

private:
  std::vector< std::vector<T> > Matrix_;
  std::size_t Width_;
  std::size_t Height_;

};


