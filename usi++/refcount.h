/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2015 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
 *
 * libusi++ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libusi++ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with psc.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef usipp_refcount_h
#define usipp_refcount_h

#include <stdio.h>

namespace usipp {


/*! \class ref_count
 *  \brief  A simple ref counter class, used by Layer2{} assignment/copy constructor
 *          to handle RX/TX objects
 *  \example refcount.cc
 */
template<typename T>
class ref_count {
	T *d_ptr;
	int *d_count;

public:

	/*! do not use with arrays, only with single objects, expects a POINTER to T */
	explicit ref_count(T *ptr = NULL)
	 : d_ptr(ptr), d_count(new int(1))
	{
	}


	/*! destructor, automatically clears if no more users */
	~ref_count()
	{
		if (--*d_count <= 0) {
			delete d_ptr;
			delete d_count;
		}
	}

	/*! assign a ref_count object to another, automatically inc counter */
	ref_count<T> &operator=(const ref_count<T> &rhs)
	{
		if (this == &rhs)
			return *this;

		if (--*d_count <= 0) {
			delete d_ptr;
			delete d_count;
		}
		d_ptr = rhs.ptr();
		d_count = rhs.count();
		++*d_count;
		return *this;
	}

	/*! ref_count copy constructor, automatically inc counter */
	ref_count(const ref_count<T> &rhs)
	{
		if (this == &rhs)
			return;

		d_ptr = rhs.ptr();
		d_count = rhs.count();
		++*d_count;
	}

	/*! one more user */
	int inc()
	{
		return ++*d_count;
	}

	/*! one user less */
	int dec()
	{
		return --*d_count;
	}

	/*! how many users? */
	int use()
	{
		return *d_count;
	}

	/*! same as operator->() */
	T *ptr() const
	{
		return d_ptr;
	}

	/*! return ref-counted object ptr */
	T *operator->()
	{
		return d_ptr;
	}

	/*! return counter storage (needed for assignments) */
	int *count() const
	{
		return d_count;
	}

};

} // namespace

#endif


